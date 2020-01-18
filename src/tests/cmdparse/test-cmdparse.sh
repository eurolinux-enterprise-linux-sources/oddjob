#!/bin/bash
tmpfile1=`mktemp ${TMPDIR:-/tmp}/cmdparseXXXXXX`
if test -z "$tmpfile1" ; then
	echo "Error creating temporary file!"
	exit 1
fi
tmpfile2=`mktemp ${TMPDIR:-/tmp}/cmdparseXXXXXX`
if test -z "$tmpfile2" ; then
	echo "Error creating temporary file!"
	rm -f "$tmpfile1"
	exit 1
fi
out1=`mktemp ${TMPDIR:-/tmp}/cmdparseXXXXXX`
if test -z "$out1" ; then
	echo "Error creating temporary file!"
	rm -f "$tmpfile1"
	rm -f "$tmpfile2"
	exit 1
fi
out2=`mktemp ${TMPDIR:-/tmp}/cmdparseXXXXXX`
if test -z "$out2" ; then
	echo "Error creating temporary file!"
	rm -f "$out1"
	rm -f "$tmpfile1"
	rm -f "$tmpfile2"
	exit 1
fi
trap 'rm -f "$out1" "$out2" "$tmpfile1" "$tmpfile2"' EXIT
cat > $tmpfile1 << EOF
abc def ghi		"xyz"
"abc" def 'ghi'		"xyz"
"a'bcdef'ghi"		"xyz"
'a"bcdef"ghi'		"xyz"
'a"bc'd'ef"ghi'		"xyz"
'a\"bc'd'ef\"ghi'	"xyz"
'a"bc\'d\'ef"ghi'	"xyz"
'a\"bc\'d\'ef\"ghi'	"xyz"
'a\\"bc\'d\'ef\\"ghi'	"xyz"
EOF
awk '{ print "for a in  ", $0 , " ; do echo $a >> '$out1'; done" }' $tmpfile1 > $tmpfile2
> $out1
i=1
while test $i -le `wc -l < $tmpfile2` ; do
	echo $i ----- >> $out1
	tail -n +$i $tmpfile2 | head -n 1 | sh >> $out1 2> /dev/null
	i=`expr $i + 1`
done
> $out2
./cmdparse < $tmpfile1 > $out2 2> /dev/null
cmp $out1 $out2 || diff -u $out1 $out2
