# Frequently Asked Questions

Below you will find all frequently asked questions.

#### Are DNSCurve keys domain based?

No, they are not. In fact keys used in DNSCurve are server based.
Meaning that all domains that are hosted at the same authoritative name server should have the same DNSCurve public key prefix (i.e. `uz5...`).
An example will clarify this.

Assume you own both `example.com` and `example.org` and you host — to simplify the story a bit — both domains on one authoritative name server: `ns.example.net`.
If you are putting CurveDNS in front of this name server, you only have to generate one keypair.
The name servers of both domains will therefore change to (for example): `uz52gs53blkwtykrqpvh4mzf8jqjs278yfd956bgudck6bq5pl9hz2.ns.example.net`.

#### Why did CurveDNS' initial release get the version number 0.86?

You might not believe it, but actually there are programmers these days that said 'Hello World' in 1986.


## Other questions?

Is the question you had in mind not answered at this page at all?
Be sure to contact the [developers](../README.md#people).
