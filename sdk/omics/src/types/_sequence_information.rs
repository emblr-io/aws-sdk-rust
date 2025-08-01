// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about a sequence.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SequenceInformation {
    /// <p>The sequence's total read count.</p>
    pub total_read_count: ::std::option::Option<i64>,
    /// <p>The sequence's total base count.</p>
    pub total_base_count: ::std::option::Option<i64>,
    /// <p>Where the sequence originated.</p>
    pub generated_from: ::std::option::Option<::std::string::String>,
    /// <p>The sequence's alignment setting.</p>
    pub alignment: ::std::option::Option<::std::string::String>,
}
impl SequenceInformation {
    /// <p>The sequence's total read count.</p>
    pub fn total_read_count(&self) -> ::std::option::Option<i64> {
        self.total_read_count
    }
    /// <p>The sequence's total base count.</p>
    pub fn total_base_count(&self) -> ::std::option::Option<i64> {
        self.total_base_count
    }
    /// <p>Where the sequence originated.</p>
    pub fn generated_from(&self) -> ::std::option::Option<&str> {
        self.generated_from.as_deref()
    }
    /// <p>The sequence's alignment setting.</p>
    pub fn alignment(&self) -> ::std::option::Option<&str> {
        self.alignment.as_deref()
    }
}
impl SequenceInformation {
    /// Creates a new builder-style object to manufacture [`SequenceInformation`](crate::types::SequenceInformation).
    pub fn builder() -> crate::types::builders::SequenceInformationBuilder {
        crate::types::builders::SequenceInformationBuilder::default()
    }
}

/// A builder for [`SequenceInformation`](crate::types::SequenceInformation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SequenceInformationBuilder {
    pub(crate) total_read_count: ::std::option::Option<i64>,
    pub(crate) total_base_count: ::std::option::Option<i64>,
    pub(crate) generated_from: ::std::option::Option<::std::string::String>,
    pub(crate) alignment: ::std::option::Option<::std::string::String>,
}
impl SequenceInformationBuilder {
    /// <p>The sequence's total read count.</p>
    pub fn total_read_count(mut self, input: i64) -> Self {
        self.total_read_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sequence's total read count.</p>
    pub fn set_total_read_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.total_read_count = input;
        self
    }
    /// <p>The sequence's total read count.</p>
    pub fn get_total_read_count(&self) -> &::std::option::Option<i64> {
        &self.total_read_count
    }
    /// <p>The sequence's total base count.</p>
    pub fn total_base_count(mut self, input: i64) -> Self {
        self.total_base_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sequence's total base count.</p>
    pub fn set_total_base_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.total_base_count = input;
        self
    }
    /// <p>The sequence's total base count.</p>
    pub fn get_total_base_count(&self) -> &::std::option::Option<i64> {
        &self.total_base_count
    }
    /// <p>Where the sequence originated.</p>
    pub fn generated_from(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.generated_from = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Where the sequence originated.</p>
    pub fn set_generated_from(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.generated_from = input;
        self
    }
    /// <p>Where the sequence originated.</p>
    pub fn get_generated_from(&self) -> &::std::option::Option<::std::string::String> {
        &self.generated_from
    }
    /// <p>The sequence's alignment setting.</p>
    pub fn alignment(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alignment = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The sequence's alignment setting.</p>
    pub fn set_alignment(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alignment = input;
        self
    }
    /// <p>The sequence's alignment setting.</p>
    pub fn get_alignment(&self) -> &::std::option::Option<::std::string::String> {
        &self.alignment
    }
    /// Consumes the builder and constructs a [`SequenceInformation`](crate::types::SequenceInformation).
    pub fn build(self) -> crate::types::SequenceInformation {
        crate::types::SequenceInformation {
            total_read_count: self.total_read_count,
            total_base_count: self.total_base_count,
            generated_from: self.generated_from,
            alignment: self.alignment,
        }
    }
}
