// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Filters to search for the associated transcript.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociatedTranscriptFilter {
    /// <p>The name of the field to use for filtering. The allowed names are IntentId and SlotTypeId.</p>
    pub name: crate::types::AssociatedTranscriptFilterName,
    /// <p>The values to use to filter the transcript.</p>
    pub values: ::std::vec::Vec<::std::string::String>,
}
impl AssociatedTranscriptFilter {
    /// <p>The name of the field to use for filtering. The allowed names are IntentId and SlotTypeId.</p>
    pub fn name(&self) -> &crate::types::AssociatedTranscriptFilterName {
        &self.name
    }
    /// <p>The values to use to filter the transcript.</p>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
}
impl AssociatedTranscriptFilter {
    /// Creates a new builder-style object to manufacture [`AssociatedTranscriptFilter`](crate::types::AssociatedTranscriptFilter).
    pub fn builder() -> crate::types::builders::AssociatedTranscriptFilterBuilder {
        crate::types::builders::AssociatedTranscriptFilterBuilder::default()
    }
}

/// A builder for [`AssociatedTranscriptFilter`](crate::types::AssociatedTranscriptFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociatedTranscriptFilterBuilder {
    pub(crate) name: ::std::option::Option<crate::types::AssociatedTranscriptFilterName>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AssociatedTranscriptFilterBuilder {
    /// <p>The name of the field to use for filtering. The allowed names are IntentId and SlotTypeId.</p>
    /// This field is required.
    pub fn name(mut self, input: crate::types::AssociatedTranscriptFilterName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the field to use for filtering. The allowed names are IntentId and SlotTypeId.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::AssociatedTranscriptFilterName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the field to use for filtering. The allowed names are IntentId and SlotTypeId.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::AssociatedTranscriptFilterName> {
        &self.name
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The values to use to filter the transcript.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The values to use to filter the transcript.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The values to use to filter the transcript.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`AssociatedTranscriptFilter`](crate::types::AssociatedTranscriptFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::AssociatedTranscriptFilterBuilder::name)
    /// - [`values`](crate::types::builders::AssociatedTranscriptFilterBuilder::values)
    pub fn build(self) -> ::std::result::Result<crate::types::AssociatedTranscriptFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AssociatedTranscriptFilter {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AssociatedTranscriptFilter",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building AssociatedTranscriptFilter",
                )
            })?,
        })
    }
}
