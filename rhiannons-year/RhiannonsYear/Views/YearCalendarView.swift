import SwiftUI

struct YearCalendarView: View {
    @EnvironmentObject private var store: ClipStore
    @EnvironmentObject private var settings: AppSettings

    @State private var visibleMonth: Date = Date()
    @State private var selectedClip: DayClip?

    private let calendar = Calendar.current
    private let columns = Array(repeating: GridItem(.flexible(), spacing: 8), count: 7)

    var body: some View {
        ZStack {
            SkyBackground()

            VStack(spacing: 20) {
                Text("My calendar")
                    .font(.custom(AppTheme.brandFont, size: 36).weight(.heavy))
                    .foregroundStyle(AppTheme.ink)
                    .padding(.top, 8)

                HStack {
                    Button {
                        shiftMonth(by: -1)
                    } label: {
                        Image(systemName: "chevron.left.circle.fill")
                            .font(.system(size: 28))
                            .foregroundStyle(AppTheme.meadow)
                    }

                    Spacer()

                    Text(monthTitle)
                        .font(.custom(AppTheme.bodyFont, size: 22).weight(.bold))
                        .foregroundStyle(AppTheme.ink)

                    Spacer()

                    Button {
                        shiftMonth(by: 1)
                    } label: {
                        Image(systemName: "chevron.right.circle.fill")
                            .font(.system(size: 28))
                            .foregroundStyle(AppTheme.meadow)
                    }
                }
                .padding(.horizontal, 28)

                LazyVGrid(columns: columns, spacing: 10) {
                    ForEach(weekdaySymbols, id: \.self) { symbol in
                        Text(symbol)
                            .font(.custom(AppTheme.bodyFont, size: 13).weight(.semibold))
                            .foregroundStyle(AppTheme.softInk)
                    }

                    ForEach(daysInMonth, id: \.self) { day in
                        dayCell(for: day)
                    }
                }
                .padding(.horizontal, 20)

                Spacer()

                Text("\(store.recordedCount) sunny days saved")
                    .font(.custom(AppTheme.bodyFont, size: 18).weight(.medium))
                    .foregroundStyle(AppTheme.softInk)
                    .padding(.bottom, 24)
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $selectedClip) { clip in
            DayPlayerView(clip: clip)
                .environmentObject(store)
        }
    }

    private var monthTitle: String {
        let formatter = DateFormatter()
        formatter.dateFormat = "MMMM yyyy"
        return formatter.string(from: visibleMonth)
    }

    private var weekdaySymbols: [String] {
        let symbols = calendar.veryShortWeekdaySymbols
        let first = calendar.firstWeekday - 1
        return Array(symbols[first...]) + Array(symbols[..<first])
    }

    private var daysInMonth: [Date?] {
        guard
            let monthInterval = calendar.dateInterval(of: .month, for: visibleMonth),
            let firstWeekday = calendar.dateComponents([.weekday], from: monthInterval.start).weekday
        else { return [] }

        let leading = (firstWeekday - calendar.firstWeekday + 7) % 7
        var days: [Date?] = Array(repeating: nil, count: leading)

        var cursor = monthInterval.start
        while cursor < monthInterval.end {
            days.append(cursor)
            cursor = calendar.date(byAdding: .day, value: 1, to: cursor) ?? monthInterval.end
        }
        return days
    }

    @ViewBuilder
    private func dayCell(for day: Date?) -> some View {
        if let day {
            let clip = store.clip(for: day)
            let isToday = calendar.isDateInToday(day)
            Button {
                if let clip { selectedClip = clip }
            } label: {
                ZStack {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(clip != nil ? AppTheme.meadow : AppTheme.cream.opacity(0.7))
                    VStack(spacing: 2) {
                        Text("\(calendar.component(.day, from: day))")
                            .font(.custom(AppTheme.bodyFont, size: 18).weight(.bold))
                            .foregroundStyle(clip != nil ? .white : AppTheme.ink)
                        if clip != nil {
                            Image(systemName: "play.fill")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundStyle(.white.opacity(0.9))
                        }
                    }
                }
                .frame(height: 52)
                .overlay {
                    if isToday {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .stroke(AppTheme.coral, lineWidth: 3)
                    }
                }
            }
            .buttonStyle(.plain)
            .disabled(clip == nil)
        } else {
            Color.clear.frame(height: 52)
        }
    }

    private func shiftMonth(by value: Int) {
        if let next = calendar.date(byAdding: .month, value: value, to: visibleMonth) {
            visibleMonth = next
        }
    }
}
