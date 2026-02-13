#pragma once

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#include <iostream>
#include <stdio.h>

namespace dlltools::cli {

/// Console colour codes
enum class Colour {
    Default = 0,
    Black = 30,
    Red = 31,
    Green = 32,
    Yellow = 33,
    Blue = 34,
    Magenta = 35,
    Cyan = 36,
    White = 37,
    BrightBlack = 90,
    BrightRed = 91,
    BrightGreen = 92,
    BrightYellow = 93,
    BrightBlue = 94,
    BrightMagenta = 95,
    BrightCyan = 96,
    BrightWhite = 97
};

/// Console text style
enum class Style {
    Default = 0,
    Bold = 1,
    Dim = 2,
    Underline = 4,
    Blink = 5,
    Reverse = 7
};

/// RAII class for coloured output
class ColourScope {
public:
    ColourScope(Colour fg, Colour bg = Colour::Default, Style style = Style::Default)
        : active_(should_enable())
    {
        if (active_) {
            apply_colour(fg, bg, style);
        }
    }
    
    ~ColourScope() {
        if (active_) {
            reset_colour();
        }
    }
    
    /// Check if colours should be enabled
    static bool should_enable() noexcept {
        // Check if stdout is a terminal
#ifdef _WIN32
        return _isatty(_fileno(stdout)) != 0;
#else
        return isatty(STDOUT_FILENO) != 0;
#endif
    }
    
    /// Enable/disable colours globally
    static void set_enabled(bool enabled) noexcept {
        enabled_ = enabled;
    }
    
    /// Check if colours are globally enabled
    static bool is_enabled() noexcept {
        return enabled_;
    }
    
private:
    void apply_colour(Colour fg, Colour bg, Style style) {
        (void)bg; // Background colour not yet implemented for Windows
#ifdef _WIN32
        // Windows console API approach
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole == INVALID_HANDLE_VALUE) return;
        
        CONSOLE_SCREEN_BUFFER_INFO info;
        if (!GetConsoleScreenBufferInfo(hConsole, &info)) return;
        
        // Save original attributes
        original_attrs_ = info.wAttributes;
        
        // Build new attributes
        WORD attrs = 0;
        
        // Map ANSI colours to Windows colours
        auto map_colour = [](Colour c) -> WORD {
            switch (c) {
                case Colour::Black:         return 0;
                case Colour::Red:           return FOREGROUND_RED;
                case Colour::Green:         return FOREGROUND_GREEN;
                case Colour::Yellow:        return FOREGROUND_RED | FOREGROUND_GREEN;
                case Colour::Blue:          return FOREGROUND_BLUE;
                case Colour::Magenta:       return FOREGROUND_RED | FOREGROUND_BLUE;
                case Colour::Cyan:          return FOREGROUND_GREEN | FOREGROUND_BLUE;
                case Colour::White:         return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
                case Colour::BrightBlack:   return 0 | FOREGROUND_INTENSITY;
                case Colour::BrightRed:     return FOREGROUND_RED | FOREGROUND_INTENSITY;
                case Colour::BrightGreen:   return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                case Colour::BrightYellow:  return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                case Colour::BrightBlue:    return FOREGROUND_BLUE | FOREGROUND_INTENSITY;
                case Colour::BrightMagenta: return FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
                case Colour::BrightCyan:    return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
                case Colour::BrightWhite:   return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
                default:                    return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
            }
        };
        
        attrs = map_colour(fg);
        
        if (style == Style::Bold) {
            attrs |= FOREGROUND_INTENSITY;
        }
        
        SetConsoleTextAttribute(hConsole, attrs);
#else
        // ANSI escape codes for Unix
        if (style != Style::Default) {
            std::cout << "\033[" << static_cast<int>(style) << ";";
        } else {
            std::cout << "\033[";
        }
        
        std::cout << static_cast<int>(fg);
        
        if (bg != Colour::Default) {
            std::cout << ";" << (static_cast<int>(bg) + 10);  // Background codes are foreground + 10
        }
        
        std::cout << "m";
#endif
    }
    
    void reset_colour() {
#ifdef _WIN32
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole != INVALID_HANDLE_VALUE) {
            SetConsoleTextAttribute(hConsole, original_attrs_);
        }
#else
        std::cout << "\033[0m";
#endif
    }
    
    bool active_;
#ifdef _WIN32
    WORD original_attrs_ = 0;
#endif
    static bool enabled_;
};

// Static member definition
inline bool ColourScope::enabled_ = true;

/// Helper functions for common colour operations
namespace colours {

/// Print text in a specific colour
inline void print(Colour colour, std::string_view text) {
    ColourScope scope(colour);
    std::cout << text;
}

/// Print text in a colour with background
inline void print(Colour fg, Colour bg, std::string_view text) {
    ColourScope scope(fg, bg);
    std::cout << text;
}

/// Print a header (bright cyan, bold)
inline void header(std::string_view text) {
    ColourScope scope(Colour::BrightCyan, Colour::Default, Style::Bold);
    std::cout << text;
}

/// Print a section title (bright yellow)
inline void title(std::string_view text) {
    ColourScope scope(Colour::BrightYellow);
    std::cout << text;
}

/// Print a success message (green)
inline void success(std::string_view text) {
    ColourScope scope(Colour::Green);
    std::cout << text;
}

/// Print a warning (yellow)
inline void warning(std::string_view text) {
    ColourScope scope(Colour::Yellow);
    std::cout << text;
}

/// Print an error (red)
inline void error(std::string_view text) {
    ColourScope scope(Colour::Red);
    std::cout << text;
}

/// Print a value (cyan)
inline void value(std::string_view text) {
    ColourScope scope(Colour::Cyan);
    std::cout << text;
}

/// Print a label (bright blue)
inline void label(std::string_view text) {
    ColourScope scope(Colour::BrightBlue);
    std::cout << text;
}

/// Print a highlight (bright green)
inline void highlight(std::string_view text) {
    ColourScope scope(Colour::BrightGreen);
    std::cout << text;
}

/// Print a dimmed text (dim style)
inline void dim(std::string_view text) {
    ColourScope scope(Colour::Default, Colour::Default, Style::Dim);
    std::cout << text;
}

/// Print a high entropy warning (bright red)
inline void high_entropy(std::string_view text) {
    ColourScope scope(Colour::BrightRed);
    std::cout << text;
}

/// Print security status - enabled (green)
inline void security_enabled(std::string_view text) {
    ColourScope scope(Colour::Green);
    std::cout << text;
}

/// Print security status - disabled (red)
inline void security_disabled(std::string_view text) {
    ColourScope scope(Colour::Red);
    std::cout << text;
}

/// Print a DLL name (bright magenta)
inline void dll_name(std::string_view text) {
    ColourScope scope(Colour::BrightMagenta);
    std::cout << text;
}

/// Print a function name (white)
inline void function_name(std::string_view text) {
    ColourScope scope(Colour::White);
    std::cout << text;
}

/// Print an ordinal (bright black)
inline void ordinal(std::string_view text) {
    ColourScope scope(Colour::BrightBlack);
    std::cout << text;
}

/// Print an address (cyan)
inline void address(std::string_view text) {
    ColourScope scope(Colour::Cyan);
    std::cout << text;
}

} // namespace colours

} // namespace dlltools::cli
