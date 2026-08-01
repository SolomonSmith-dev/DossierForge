#!/usr/bin/env bash
# Offline sanity check for the Rhiannon's Year Xcode project layout.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
fail=0

require() {
  if [[ ! -e "$ROOT/$1" ]]; then
    echo "MISSING: $1"
    fail=1
  else
    echo "ok  $1"
  fi
}

require "RhiannonsYear.xcodeproj/project.pbxproj"
require "RhiannonsYear/RhiannonsYearApp.swift"
require "RhiannonsYear/Info.plist"
require "RhiannonsYear/Models/DayClip.swift"
require "RhiannonsYear/Models/AppSettings.swift"
require "RhiannonsYear/Services/ClipStore.swift"
require "RhiannonsYear/Services/CameraService.swift"
require "RhiannonsYear/Services/VideoStitcher.swift"
require "RhiannonsYear/Services/NotificationService.swift"
require "RhiannonsYear/Views/ContentView.swift"
require "RhiannonsYear/Views/HomeView.swift"
require "RhiannonsYear/Views/RecordView.swift"
require "RhiannonsYear/Views/CameraPreviewView.swift"
require "RhiannonsYear/Views/YearCalendarView.swift"
require "RhiannonsYear/Views/DayPlayerView.swift"
require "RhiannonsYear/Views/ExportYearView.swift"
require "RhiannonsYear/Views/ParentCornerView.swift"
require "RhiannonsYear/Theme/AppTheme.swift"
require "RhiannonsYear/Assets.xcassets/Contents.json"
require "README.md"

# Ensure project references core sources
for symbol in ClipStore CameraService VideoStitcher HomeView RecordView ParentCornerView; do
  if ! grep -q "$symbol.swift" "$ROOT/RhiannonsYear.xcodeproj/project.pbxproj"; then
    echo "PBX missing reference: $symbol.swift"
    fail=1
  fi
done

# Ensure privacy strings exist
for key in NSCameraUsageDescription NSMicrophoneUsageDescription NSPhotoLibraryAddUsageDescription; do
  if ! grep -q "$key" "$ROOT/RhiannonsYear/Info.plist"; then
    echo "Info.plist missing $key"
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "Structure check FAILED"
  exit 1
fi
echo "Structure check PASSED"
