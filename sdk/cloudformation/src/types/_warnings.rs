// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains any warnings returned by the <code>GetTemplateSummary</code> API action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Warnings {
    /// <p>A list of all of the unrecognized resource types. This is only returned if the <code>TemplateSummaryConfig</code> parameter has the <code>TreatUnrecognizedResourceTypesAsWarning</code> configuration set to <code>True</code>.</p>
    pub unrecognized_resource_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl Warnings {
    /// <p>A list of all of the unrecognized resource types. This is only returned if the <code>TemplateSummaryConfig</code> parameter has the <code>TreatUnrecognizedResourceTypesAsWarning</code> configuration set to <code>True</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.unrecognized_resource_types.is_none()`.
    pub fn unrecognized_resource_types(&self) -> &[::std::string::String] {
        self.unrecognized_resource_types.as_deref().unwrap_or_default()
    }
}
impl Warnings {
    /// Creates a new builder-style object to manufacture [`Warnings`](crate::types::Warnings).
    pub fn builder() -> crate::types::builders::WarningsBuilder {
        crate::types::builders::WarningsBuilder::default()
    }
}

/// A builder for [`Warnings`](crate::types::Warnings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WarningsBuilder {
    pub(crate) unrecognized_resource_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl WarningsBuilder {
    /// Appends an item to `unrecognized_resource_types`.
    ///
    /// To override the contents of this collection use [`set_unrecognized_resource_types`](Self::set_unrecognized_resource_types).
    ///
    /// <p>A list of all of the unrecognized resource types. This is only returned if the <code>TemplateSummaryConfig</code> parameter has the <code>TreatUnrecognizedResourceTypesAsWarning</code> configuration set to <code>True</code>.</p>
    pub fn unrecognized_resource_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.unrecognized_resource_types.unwrap_or_default();
        v.push(input.into());
        self.unrecognized_resource_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of all of the unrecognized resource types. This is only returned if the <code>TemplateSummaryConfig</code> parameter has the <code>TreatUnrecognizedResourceTypesAsWarning</code> configuration set to <code>True</code>.</p>
    pub fn set_unrecognized_resource_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.unrecognized_resource_types = input;
        self
    }
    /// <p>A list of all of the unrecognized resource types. This is only returned if the <code>TemplateSummaryConfig</code> parameter has the <code>TreatUnrecognizedResourceTypesAsWarning</code> configuration set to <code>True</code>.</p>
    pub fn get_unrecognized_resource_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.unrecognized_resource_types
    }
    /// Consumes the builder and constructs a [`Warnings`](crate::types::Warnings).
    pub fn build(self) -> crate::types::Warnings {
        crate::types::Warnings {
            unrecognized_resource_types: self.unrecognized_resource_types,
        }
    }
}
