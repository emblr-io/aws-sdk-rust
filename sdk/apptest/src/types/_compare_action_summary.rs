// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the compare action summary.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CompareActionSummary {
    /// <p>The type of the compare action summary.</p>
    pub r#type: ::std::option::Option<crate::types::File>,
}
impl CompareActionSummary {
    /// <p>The type of the compare action summary.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::File> {
        self.r#type.as_ref()
    }
}
impl CompareActionSummary {
    /// Creates a new builder-style object to manufacture [`CompareActionSummary`](crate::types::CompareActionSummary).
    pub fn builder() -> crate::types::builders::CompareActionSummaryBuilder {
        crate::types::builders::CompareActionSummaryBuilder::default()
    }
}

/// A builder for [`CompareActionSummary`](crate::types::CompareActionSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CompareActionSummaryBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::File>,
}
impl CompareActionSummaryBuilder {
    /// <p>The type of the compare action summary.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::File) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the compare action summary.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::File>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the compare action summary.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::File> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`CompareActionSummary`](crate::types::CompareActionSummary).
    pub fn build(self) -> crate::types::CompareActionSummary {
        crate::types::CompareActionSummary { r#type: self.r#type }
    }
}
