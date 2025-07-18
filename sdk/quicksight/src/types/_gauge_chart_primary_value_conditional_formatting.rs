// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The conditional formatting for the primary value of a <code>GaugeChartVisual</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GaugeChartPrimaryValueConditionalFormatting {
    /// <p>The conditional formatting of the primary value text color.</p>
    pub text_color: ::std::option::Option<crate::types::ConditionalFormattingColor>,
    /// <p>The conditional formatting of the primary value icon.</p>
    pub icon: ::std::option::Option<crate::types::ConditionalFormattingIcon>,
}
impl GaugeChartPrimaryValueConditionalFormatting {
    /// <p>The conditional formatting of the primary value text color.</p>
    pub fn text_color(&self) -> ::std::option::Option<&crate::types::ConditionalFormattingColor> {
        self.text_color.as_ref()
    }
    /// <p>The conditional formatting of the primary value icon.</p>
    pub fn icon(&self) -> ::std::option::Option<&crate::types::ConditionalFormattingIcon> {
        self.icon.as_ref()
    }
}
impl GaugeChartPrimaryValueConditionalFormatting {
    /// Creates a new builder-style object to manufacture [`GaugeChartPrimaryValueConditionalFormatting`](crate::types::GaugeChartPrimaryValueConditionalFormatting).
    pub fn builder() -> crate::types::builders::GaugeChartPrimaryValueConditionalFormattingBuilder {
        crate::types::builders::GaugeChartPrimaryValueConditionalFormattingBuilder::default()
    }
}

/// A builder for [`GaugeChartPrimaryValueConditionalFormatting`](crate::types::GaugeChartPrimaryValueConditionalFormatting).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GaugeChartPrimaryValueConditionalFormattingBuilder {
    pub(crate) text_color: ::std::option::Option<crate::types::ConditionalFormattingColor>,
    pub(crate) icon: ::std::option::Option<crate::types::ConditionalFormattingIcon>,
}
impl GaugeChartPrimaryValueConditionalFormattingBuilder {
    /// <p>The conditional formatting of the primary value text color.</p>
    pub fn text_color(mut self, input: crate::types::ConditionalFormattingColor) -> Self {
        self.text_color = ::std::option::Option::Some(input);
        self
    }
    /// <p>The conditional formatting of the primary value text color.</p>
    pub fn set_text_color(mut self, input: ::std::option::Option<crate::types::ConditionalFormattingColor>) -> Self {
        self.text_color = input;
        self
    }
    /// <p>The conditional formatting of the primary value text color.</p>
    pub fn get_text_color(&self) -> &::std::option::Option<crate::types::ConditionalFormattingColor> {
        &self.text_color
    }
    /// <p>The conditional formatting of the primary value icon.</p>
    pub fn icon(mut self, input: crate::types::ConditionalFormattingIcon) -> Self {
        self.icon = ::std::option::Option::Some(input);
        self
    }
    /// <p>The conditional formatting of the primary value icon.</p>
    pub fn set_icon(mut self, input: ::std::option::Option<crate::types::ConditionalFormattingIcon>) -> Self {
        self.icon = input;
        self
    }
    /// <p>The conditional formatting of the primary value icon.</p>
    pub fn get_icon(&self) -> &::std::option::Option<crate::types::ConditionalFormattingIcon> {
        &self.icon
    }
    /// Consumes the builder and constructs a [`GaugeChartPrimaryValueConditionalFormatting`](crate::types::GaugeChartPrimaryValueConditionalFormatting).
    pub fn build(self) -> crate::types::GaugeChartPrimaryValueConditionalFormatting {
        crate::types::GaugeChartPrimaryValueConditionalFormatting {
            text_color: self.text_color,
            icon: self.icon,
        }
    }
}
