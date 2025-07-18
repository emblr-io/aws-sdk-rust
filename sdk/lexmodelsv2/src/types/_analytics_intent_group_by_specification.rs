// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the category by which to group the intents.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalyticsIntentGroupBySpecification {
    /// <p>Specifies whether to group the intent stages by their name or their end state.</p>
    pub name: crate::types::AnalyticsIntentField,
}
impl AnalyticsIntentGroupBySpecification {
    /// <p>Specifies whether to group the intent stages by their name or their end state.</p>
    pub fn name(&self) -> &crate::types::AnalyticsIntentField {
        &self.name
    }
}
impl AnalyticsIntentGroupBySpecification {
    /// Creates a new builder-style object to manufacture [`AnalyticsIntentGroupBySpecification`](crate::types::AnalyticsIntentGroupBySpecification).
    pub fn builder() -> crate::types::builders::AnalyticsIntentGroupBySpecificationBuilder {
        crate::types::builders::AnalyticsIntentGroupBySpecificationBuilder::default()
    }
}

/// A builder for [`AnalyticsIntentGroupBySpecification`](crate::types::AnalyticsIntentGroupBySpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalyticsIntentGroupBySpecificationBuilder {
    pub(crate) name: ::std::option::Option<crate::types::AnalyticsIntentField>,
}
impl AnalyticsIntentGroupBySpecificationBuilder {
    /// <p>Specifies whether to group the intent stages by their name or their end state.</p>
    /// This field is required.
    pub fn name(mut self, input: crate::types::AnalyticsIntentField) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to group the intent stages by their name or their end state.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::AnalyticsIntentField>) -> Self {
        self.name = input;
        self
    }
    /// <p>Specifies whether to group the intent stages by their name or their end state.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::AnalyticsIntentField> {
        &self.name
    }
    /// Consumes the builder and constructs a [`AnalyticsIntentGroupBySpecification`](crate::types::AnalyticsIntentGroupBySpecification).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::AnalyticsIntentGroupBySpecificationBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::AnalyticsIntentGroupBySpecification, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AnalyticsIntentGroupBySpecification {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AnalyticsIntentGroupBySpecification",
                )
            })?,
        })
    }
}
