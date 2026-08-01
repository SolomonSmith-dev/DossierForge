# Rhiannon's Year

A kid-friendly iPad app for recording one **5-second video every day**, then stitching those clips into a year-end movie.

Built for Rhiannon (age 8): big buttons, calm sky UI, no accounts, no cloud, no social.

## What it does

- **Record today** — front camera, 3-2-1 countdown, hard stop at 5 seconds, review + save or retake
- **Calendar** — tap any saved day to replay that clip
- **Make my year** — concatenate all clips in date order into one MP4; save to Photos or share to Files
- **Parent corner** (gear icon, PIN `1234` by default) — rename, reminders, change PIN, delete a day, share all clips

Videos stay on the iPad under the app’s Documents folder (`DailyClips/YYYY-MM-DD.mp4`).

## Requirements

- Mac with **Xcode 15+**
- iPad (or iPhone) on **iOS 17+**
- Apple ID for free device signing (or a paid Developer account for TestFlight)

## Open & run on her iPad

1. Copy or clone this folder onto a Mac.
2. Open `RhiannonsYear.xcodeproj` in Xcode.
3. Select the **RhiannonsYear** target → **Signing & Capabilities**.
4. Choose your **Team** (personal Apple ID works for cable installs).
5. Plug in the iPad, trust the computer, select the iPad as the run destination.
6. Press **Run**. On first launch, allow **Camera**, **Microphone**, and (later) **Photos** when exporting.

Optional: Product → Archive → Distribute App → **TestFlight** for wireless installs.

## Parent tips

- Change the PIN in Parent corner after first unlock.
- Set a daily reminder time (default 6:00 PM).
- Use **Share all clips** periodically as a backup to a Mac or Files.
- At any point, **Make my year** builds the film from whatever days exist so far.

## Project layout

```
rhiannons-year/
  RhiannonsYear.xcodeproj/
  RhiannonsYear/
    RhiannonsYearApp.swift
    Models/          # DayClip, AppSettings
    Services/        # ClipStore, Camera, stitch, notifications
    Views/           # Home, Record, Calendar, Export, Parent
    Theme/           # Colors & sky background
    Info.plist
```

## Privacy

- No login, analytics, or network features
- Camera/mic only for recording; Photos only when you save the year film
- Everything is local unless you explicitly share or export

## Note for this repo

This app lives in `rhiannons-year/` as a standalone Xcode project. It is separate from the DossierForge Flask app in the repository root. Building and running requires a Mac with Xcode; this Linux environment only hosts the source.
