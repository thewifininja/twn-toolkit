# Shared UI controls

## Actions and navigation

Reuse the existing component and theme classes whenever adding a control. In
action rows and menus, navigation uses `<a class="button-link secondary">`;
operations use `<button class="secondary">`. Reserve ordinary text links for
inline prose. Keep destructive operations on the existing `danger` treatment.
Do not invent page-specific button colors, padding, or typography.

Saved-profile overflow menus use `.compact-profile-more`; links and buttons
must share full-width, left-aligned action styling. Conditional actions must
retain their `hidden` behavior. Check hover, visible keyboard focus, keyboard
activation, and mobile layout against adjacent controls before shipping.

## Fields

`static/appearance.css` owns sizing for ordinary single-line inputs, native
single-choice selects, and enhanced `.toolkit-select-trigger` controls. Use these
shared rules when adding a form; avoid page-specific heights, font sizes, line
heights, or vertical padding for these controls.

`--ui-field-height` combines the density's minimum height with room for the shared
text line and padding. Compact controls start at 34px, comfortable controls at
40px, and viewports at or below 900px use at least 44px. Enlarging text increases
the height when needed. The shared declarations override legacy page styles so
native inputs and enhanced selects cannot drift apart at larger text scales.

Multiline textareas share field typography and padding, while keeping their rows,
editor heights and resizing behavior. Mobile/touch fields use at least 16px text
and honor larger text scaling. The hidden terminal input capture is excluded.

Field widths belong to the form layout: paired metadata can use equal columns,
while a hostname can take more space than its port. Multi-select/list
boxes, file pickers, ranges, colors, checkboxes, radios and action buttons have
separate sizing requirements and are excluded from the single-line field rule.

For visual regression checks, compare text inputs and dropdowns at 90%, 100%,
110% and 125% text size, both densities, and desktop/mobile widths. Include
fields inside dialogs and details sections, and check for clipped text or page
overflow. New and Edit Host must share the same control treatment as other pages.
