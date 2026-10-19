# BabyOSINT — evidence (2026-10-11)

Status: not solved / no accepted flag yet. The user reported that
`d1nhdwc{hodaj_za_liku_hodaj_za_hrvatsku:zegevege_festival:wednesday:911}`
was rejected.

## Q1 and Q2

The image EXIF reports `2026:09:05 12:03:02.820000+02:00`.

Organizer's announcement:
https://www.prijatelji-zivotinja.hr/index.hr.php?id=5285

It explicitly identifies the protest as **Hodaj za Liku, hodaj za Hrvatsku**
on 5 September 2026, and the nearby festival as **ZeGeVege**, the 18th edition,
held 4–6 September at Europski trg. It explicitly announces solidarity and
discounts for protesters.

Festival website: https://www.zegevege.com/

Q1 normalization: `hodaj_za_liku_hodaj_za_hrvatsku`.
Q2 identity is established; the exact string accepted by the challenge is not.
`zegevege` is the next proposed variant. The full Croatian description is
`ZeGeVege festival održivog življenja`.

## Q3

https://bajs.informacija.hr/

The downloaded page's embedded `chartsData.weekdayDistribution` has:

| Day | Average trips |
| --- | ---: |
| Ponedjeljak / Monday | 15782.25 |
| Utorak / Tuesday | 17417.25 |
| Srijeda / Wednesday | 17493.5 |
| Četvrtak / Thursday | 12597.5 |
| Petak / Friday | 14471.5 |
| Subota / Saturday | 9422.8 |
| Nedjelja / Sunday | 8603.4 |

This is the current displayed 30-day window, not a fixed all-time dataset.
Answer supported by this snapshot: `wednesday`.

The supplied TikTok URL could not be opened by the browser tool.

## Q4

Replay: https://bajs.informacija.hr/events/inmusic
Data: https://bajs.informacija.hr/api/events/inmusic/timelapse

There are 1144 frames. The largest individual station count across every frame
is **911**. It occurs at Unix timestamp **1782250307**, i.e.
**2026-06-23 21:31:47 UTC / 23:31:47 Europe/Zagreb**.

The value is in `frames[].c[213]`; the page's embedded `INIT.names[213]` is
`INMUSIC - PRIVREMENA DO 24.6.`.

Do not use the separate `fb` field: it currently points at other station slots.
The page also currently links historical INmusic to number 21411, whose profile
now resolves to TUŠKANAC. That profile's raw history is not the INmusic record.

Reproduce maximum from the downloaded replay JSON:

```sh
jq '[.frames[] | {utc:(.t|todate), maximum:(.c|max)}] | max_by(.maximum)' /tmp/babyosint-inmusic-replay.json
```

This establishes 911 as the maximum in the public event replay (roughly
five-minute frames); it does not prove no higher value existed between samples
or outside this event.

Contemporary corroboration (849 ordinary + 60 child-seat bikes = 909 at the
time of the article, not necessarily the record):
https://www.index.hr/amp/fit/clanak/vise-od-900-ljudi-na-inmusic-doslo-bajsom/2805907.aspx

## Candidate awaiting user validation

`d1nhdwc{hodaj_za_liku_hodaj_za_hrvatsku:zegevege:wednesday:911}`

Only Q2 differs from the rejected flag. This is a formatting hypothesis,
not a claim that the flag has been accepted.
