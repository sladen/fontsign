## Synopsis

Microsoft has a digital signing standard for fonts.  Most people
don't care about this, but the presence or non-presence of
the extra 'DSIG' table affects whether MS Windows 2000 presents
to the viewer as Truetype or Opentype.  Some Opentype feature
tables are not read unless a font has a 'DSIG' table.

Most font developers and tooling therefore inserts a "dummy signature"
with zeroed checksum hashes.  In an ideal world, if the signature
block is there, it might as well be correct.  There is a specification
but specifications have a habit of varying when there are a limited
number of implementations, the aim here is:

1. Evaluate known-good signature blocks to understand the structure
2. Create a validate that can validate a signature
3. Re-generate the signatures in a deterministic/fully-understood manner

This should then open up the possibility for auto-signing fonts on
rebuild or after changes, eg. subsetting for PDF printing or for web
fonts such as Google Fonts.

## Investigation

Lets get some input.  Here's a starting point:

  ```shell
  $ sha1sum */*.ttf
  b0ccad40a8a55a49186a35777390b3c441878770  Ubuntu_0.831/Ubuntu-R.ttf
  ```

Extract the DSIG table as binary (ttx always dumps an new XML too):

  ```shell
  otfinfo -T DSIG Ubuntu_0.831/Ubuntu-R.ttf > Ubuntu-R.ttf.dsig
  ```

'strings' shows typical X.509 stuff, so likely the rest is wrapped
ASN1 too, so lets hunt for the start.  Thankfully 'dumpasn1' has an
exit code which is the number of errors encountered when attempting
the decode, so we can use that flag up plausible offsets and look for
a low number, preferably zero:

  ```shell
  for i in `seq 0 100` ; do echo SKIPPING $i ; \
    dd if=Ubuntu-R.ttf.dsig bs=1 skip=$i | dumpasn1 - && echo RESULT $i $? ; \
  done | less -S
  ```

Success with 28 octets of header skipped.  A cross-check with the
Microsoft DSIG specification seems to be confirmed that this is probably
correct:

* https://www.microsoft.com/typography/otspec/dsig.htm

As this equal to one signature and signature heading [ie. the common case]:

  ```python
  (4+2+2)+1*(4+4+4)+1*(2+2+4) = 28 # octet header
  ```

To get something human-readable `-a` is needed to dump to avoid string
truncation.  The `-l` helps with verbosity.  

  ```shell
  dd if=Ubuntu-R.ttf.dsig bs=1 skip=28 | dumpasn1 -a -l - > dump.txt
  ```
### enterprise/microsoft/fonts/.1

The only font-specific OID that is used is `1.3.6.1.4.1.311.40.1`
(`enterprise/microsoft/fonts/.1`).  Enteries generated by Dalton
Maag's `dsign` signing codebase output this a 32-bit binary string.
As of September 2016 the meaning/content of this OID is not understood.

The ASN1 block decodes with only one complaint from `dumpasn1` about a malformed bit-string under
OID `.311.40.1.*` ("Error: Spurious zero bits in bitstring.").  This OID is
not one that 'dumpasn1' already knows about, and is inside Microsoft's
private usage area.  Lets go-hunting for everything that shows up in
the dump under `.311.*`:

```
  1.3.6.1.4.1: Private usage area - http://www.alvestrand.no/objectid/1.3.6.1.4.1.html
   .311: Microsoft - http://www.alvestrand.no/objectid/1.3.6.1.4.1.311.html
    .2: Authenticode - https://support.microsoft.com/en-us/kb/287547
     .1: Software Publishing
      .4: INDIRECT_DATA
      .11: STATEMENT_TYPE
      .12: SP_OPUS_INFO
      .22: COMMERCIAL_SP_KEY_PURPOSE
      .28: LINK
    .3: Timestamp - https://support.microsoft.com/en-us/kb/287547
     .2.1: TIME_STAMP_REQUEST
    .40: Fonts - https://support.microsoft.com/en-us/kb/287547
     .1: ??
```

Yeah.  Helpful...

Interestingly if one passes `dampasn1 -r` (reverse bit-strings), then
no error is shown.  With `dampasn1 -hh` (hex dump) we can see raw octets:

```asn1
  <03 05 00 03 00 00 00>
```

This decodes to a 32-bit bit-string; `(5-1) payload octets * 8 bits - 0 padding == 32 bits` per:

```
  0x03 == bit string
  0x05 == payload octets following
  0x00 == unused bits in last octet
  0x03 == 0000 0011 ... (so either 3, or 192, or 0x03000000 ?)
```

And this gives some insight: the sanity check warning is coming
because in little endian only a single octet is required, and not a
whole 32-bit bit-field.

Now if only we know what the two (?) flags corresponded to.

However, this is from the Dalton Maag signing tool.  We can
compare what this looks like in a Microsoft internally-signed
font:

  ```shell
  wget https://www.freedesktop.org/software/fontconfig/webfonts/webfonts.tar.gz
  tar zxvf webfonts.tar.gz
  cd msfonts/
  cabextract *.exe
  for i in *.[Tt][Tt][Ff] ; do echo $i ; \
    otfinfo -T DSIG $i | dd bs=1 skip=28 | dumpasn1 -a - ; \
  done | grep -c '311 40'
  ```

which gives:

  ```
  0
  ```

Therefore old signed Microsoft fonts do not have this unidentified
entry.  Could it be OpenType only?

Or even *the* identifier for OpenType fonts that sets the magic icon
on MS Windows.

Another possibility is that it is being injected by the `mssipotf.dll`
sanity checker, as this is mentioned in:

* https://www.microsoft.com/typography/developers/dsig/dsig.htm

Grepping a large number of fonts:

  ```shell
  for i in `find ~/ -iname \*.[ot]tf | grep -v ' '` ; do echo "$i" ; \
    otfinfo -T DSIG "$i" | dd bs=1 skip=28 status=noxfer | dumpasn1 -a - ; \
  done > foo.txt
  ```

and (so far) it only appears to be Dalton Maag signed fonts.  This includes
a release of Aller signed in August 2008.

## Existing implementations

1. Microsoft Word behaves differently depending on signature block presence.

2. Microsoft Windows 2000 Font Viewer. Based on what is written, this
apparently displays a a red/green traffic based on validation of the
signature.  Microsoft suggest that the implementation is limited and
does not follow the full extent of the published specification:
> Although the OpenType font specification allows for countersigning,
> Windows 2000 does not support the authentication and verification of
> each individual signature in a font. Our font-signing tool will only
> let one publisher sign a font.
> [[microsoft]](https://www.microsoft.com/en-us/Typography/DigitalSignaturesDefault.aspx#fonts)

### Microsoft official tools - Dsig

* https://www.microsoft.com/en-us/Typography/dsigningtool.aspx (January 2003)

Microsoft's 1999-era font signing tools don't appear to function correctly
under Wine, always declaring a file's signature checking as "FAILURE".

Following Microsoft's excellent endeavours to open up legacy
intrastructure tools via Github, contact was attempted with a view to
checking what the `dsig.exe` was actually doing and/or getting the source opened up.

One may need to locate a copy of `mssign32.dll` in order to get any of
the included tool to execute.  The `makecert.exe` does appear to work;
the resulting keys and certificates it produces appear to be fairly standard,
except for a "Error: Object has zero length." warning on the first (empty) object.

## Dalton Maag tools - dsign

Dalton Maag have an internal implementation written in C, with some
wrappers to allow interfacing from Python.  In September 2016 the
technical team at Dalton Maag were helpful in offering insight into
the inner working of this codebase.

The codebase inserts the incorrectly-formed `1.3.6.1.4.1.311.40.1` OID
bitstring as a literal blob (sequence of hard-coded bytes).

Whilst this perhaps clears up the *origin* of the blob, it suggests
that the true purpose remains unclear, along with the meaning of the
two bit flags that are set in the middle of the blob.

## Fontlab / Fontographer 5

* http://old.fontlab.com/font-editor/fontographer/

This ships for MacOS X too, which would point to an internal
implementation.  The webpage states this appeared in version 5:

> NEW! Support for OpenType digital signatures (DSIG)

## Further reading

* https://technet.microsoft.com/en-us/itpro/windows/keep-secure/block-untrusted-fonts-in-enterprise
* http://www.adobe.com/devnet/opentype/afdko/topic_digital_sig_guide.html
* http://typedrawers.com/discussion/192/making-ot-ttf-layout-features-work-in-ms-word-2010
* https://forum.glyphsapp.com/t/ttf-dsig/1462/9

## Random finds

* `HKLM,"Software\Microsoft\Cryptography\OID\EncodingType 0\CryptDllFindOIDInfo\1.3.6.1.4.1.311.40.1!5"`
* `HKLM,"Software\Microsoft\Cryptography\OID\EncodingType 1\CryptDllFormatObject\1.3.6.1.4.1.311.40.1"`

# Handy recipes

  ```shell
  wget https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.c
  cc dumpasn1.c -o dumpasn1
  ttx -t DSIG -o Ubuntu-R_dsig.ttx Ubuntu-R.ttf
  openssl pkcs7 -inform PEM -outform DER -in Ubuntu-R_dsig.ttx -out Ubuntu-R_dsig.der
  ./dumpasn1 Ubuntu-R_dsig.der > Ubuntu-R_dsig.asn1
  ```
