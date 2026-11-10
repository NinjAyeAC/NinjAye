using System.Collections.Generic;

namespace NinjAye.Server;

public static class DetectionCodeMap
{
    private static readonly HashSet<uint> _groupCodes =
    [
        70, 71, 72, 74, 75, 76, 77, 78, 80, 81, 82, 83, 84, 85,
        95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
        106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
        117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128,
        138, 139, 140, 141, 142, 143, 144, 145,
        189, 192, 200, 201, 219, 220, 221, 222,
        229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    ];

    public static string Resolve(uint codeId)
    {
        var direct = codeId switch
        {
            0x17A => "protection.callback_registry.missing",
            0x182 => "protection.callback_registry.incomplete",
            0x1A0 => "protection.status.transport_failure",
            0x05 => "protection.region.private",
            0x19 => "protection.region.writable_executable",
            0x2C => "protection.process.report",
            0x81 => "protection.report.queued_task",
            0x99 => "protection.worker.startup",
            0xB2 => "protection.graphics.vtable_method",
            0xB3 => "protection.graphics.vtable_address",
            0xB4 => "protection.execution_breakpoint",
            0xB5 => "protection.recorded_breakpoint_address",
            0xB8 => "protection.process.record",
            0xB9 => "protection.process.detail",
            0xC1 => "protection.input.injected_mouse",
            0xC2 => "protection.input.injected_keyboard",
            0xC3 => "protection.input.low_interval_variation",
            0xC4 => "protection.input.continuous_window",
            0xC5 => "protection.input.repeated_sequence",
            0xC6 => "protection.input.low_code_mean",
            0xD7 => "protection.input.mixed_injected",
            0xD8 => "protection.input.keyboard_intervals",
            0xD9 => "protection.input.injected_clear_divergence",
            0xDF => "protection.input.channel_statistics",
            0xE0 => "protection.input.channel_periodic",
            0xE1 => "protection.input.channel_durations",
            0xE2 => "protection.input.short_durations",
            0xE3 => "protection.input.macro_composite",
            0x234 => "protection.challenge.repeated_without_progress",
            0x244 => "protection.module.crc_mismatch",
            0x282 => "protection.status.exchange_failure",
            0x1ED => "protection.thread.summary",
            0x22D => "protection.thread.short_period",
            0x2B1 => "protection.thread.confirmed",
            0x555 => "protection.process.handle",
            _ => null,
        };
        if (direct is not null)
        {
            return direct;
        }
        return _groupCodes.Contains(codeId)
            ? $"protection.report_group.0x{codeId:X2}"
            : $"unknown.0x{codeId:X8}";
    }
}
