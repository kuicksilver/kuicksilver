#!/usr/bin/env perl
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Applies the OpenSSL patch carried under ADR-0019 to a copy of the verified source tree, exactly: a unified diff whose files
# are named a/<path> and b/<path> (the same path), each hunk applied at the line its header names, with every context and
# removed line as it stands in the tree. No fuzz, no offset, no new, deleted or renamed files, no "\ No newline" lines. The
# text before the first "--- " line is the patch's description and is skipped. Anything else stops with an error before a
# file is written, so the tree is either patched whole or left as it was. Perl only: the build images have it (OpenSSL's
# Configure needs it), and none of them is required to have patch(1) or git.
# Usage: apply-patch.pl <patch> <tree>
use strict;
use warnings;

my ($patch, $tree) = @ARGV;
die "usage: apply-patch.pl <patch> <tree>\n" unless defined $tree && @ARGV == 2;
open(my $ph, '<', $patch) or die "apply-patch: cannot read $patch: $!\n";
my @p = <$ph>;
close $ph;

my (%new, @order);
my $i = 0;
$i++ while $i < @p && $p[$i] !~ /^--- /;
die "apply-patch: $patch holds no file\n" if $i >= @p;
while ($i < @p) {
    my ($old) = $p[$i] =~ m{^--- a/(\S+)\s*$} or die "apply-patch: line " . ($i + 1) . ": expected '--- a/<path>'\n";
    my ($nw) = ($p[$i + 1] // '') =~ m{^\+\+\+ b/(\S+)\s*$} or die "apply-patch: line " . ($i + 2) . ": expected '+++ b/<path>'\n";
    die "apply-patch: $old renamed to $nw\n" if $old ne $nw;
    die "apply-patch: unsafe path $old\n" if $old =~ m{(^|/)\.\.(/|$)} || $old =~ m{^/};
    die "apply-patch: $old patched twice\n" if exists $new{$old};
    $i += 2;
    my $file = "$tree/$old";
    open(my $fh, '<', $file) or die "apply-patch: cannot read $file: $!\n";
    my @src = <$fh>;
    close $fh;
    my @out;
    my $at = 0;    # lines of @src already copied
    while ($i < @p && $p[$i] =~ /^@@ /) {
        my ($os, $oc, $ns, $nc) = $p[$i] =~ /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/
          or die "apply-patch: line " . ($i + 1) . ": bad hunk header\n";
        $oc //= 1;
        $nc //= 1;
        $i++;
        my $start = $oc == 0 ? $os : $os - 1;    # 0-based index of the hunk's first old line
        die "apply-patch: $old: hunk at line $os overlaps the one before\n" if $start < $at;
        push @out, @src[$at .. $start - 1];
        my $pos = $start;
        my ($seen_old, $seen_new) = (0, 0);
        while ($seen_old < $oc || $seen_new < $nc) {
            die "apply-patch: $old: hunk at line $os ends early\n" if $i >= @p;
            my $l = $p[$i++];
            my ($tag, $text) = (substr($l, 0, 1), substr($l, 1));
            if ($tag eq ' ' || $tag eq '-') {
                die "apply-patch: $old: line " . ($pos + 1) . " differs from the patch's context\n"
                  if $pos >= @src || $src[$pos] ne $text;
                push @out, $text if $tag eq ' ';
                $pos++;
                $seen_old++;
                $seen_new++ if $tag eq ' ';
            } elsif ($tag eq '+') {
                push @out, $text;
                $seen_new++;
            } else {
                die "apply-patch: $old: unexpected line in the hunk at line $os: $l";
            }
        }
        die "apply-patch: $old: hunk at line $os does not match its counts\n" if $seen_old != $oc || $seen_new != $nc;
        $at = $pos;
    }
    die "apply-patch: $old has no hunk\n" if !@out && $at == 0;
    push @out, @src[$at .. $#src];
    $new{$old} = join('', @out);
    push @order, $old;
    die "apply-patch: line " . ($i + 1) . ": unexpected text after the hunks of $old\n" if $i < @p && $p[$i] !~ /^--- /;
}
for my $f (@order) {
    my $file = "$tree/$f";
    my $mode = (stat $file)[2] & 07777;
    open(my $fh, '>', "$file.ksl-patch") or die "apply-patch: cannot write $file.ksl-patch: $!\n";
    print $fh $new{$f};
    close $fh or die "apply-patch: cannot write $file.ksl-patch: $!\n";
    chmod $mode, "$file.ksl-patch";
    rename "$file.ksl-patch", $file or die "apply-patch: cannot replace $file: $!\n";
}
print "patched " . join(' ', @order) . "\n";
