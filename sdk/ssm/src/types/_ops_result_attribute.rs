// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The OpsItem data type to return.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OpsResultAttribute {
    /// <p>Name of the data type. Valid value: <code>AWS:OpsItem</code>, <code>AWS:EC2InstanceInformation</code>, <code>AWS:OpsItemTrendline</code>, or <code>AWS:ComplianceSummary</code>.</p>
    pub type_name: ::std::string::String,
}
impl OpsResultAttribute {
    /// <p>Name of the data type. Valid value: <code>AWS:OpsItem</code>, <code>AWS:EC2InstanceInformation</code>, <code>AWS:OpsItemTrendline</code>, or <code>AWS:ComplianceSummary</code>.</p>
    pub fn type_name(&self) -> &str {
        use std::ops::Deref;
        self.type_name.deref()
    }
}
impl OpsResultAttribute {
    /// Creates a new builder-style object to manufacture [`OpsResultAttribute`](crate::types::OpsResultAttribute).
    pub fn builder() -> crate::types::builders::OpsResultAttributeBuilder {
        crate::types::builders::OpsResultAttributeBuilder::default()
    }
}

/// A builder for [`OpsResultAttribute`](crate::types::OpsResultAttribute).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OpsResultAttributeBuilder {
    pub(crate) type_name: ::std::option::Option<::std::string::String>,
}
impl OpsResultAttributeBuilder {
    /// <p>Name of the data type. Valid value: <code>AWS:OpsItem</code>, <code>AWS:EC2InstanceInformation</code>, <code>AWS:OpsItemTrendline</code>, or <code>AWS:ComplianceSummary</code>.</p>
    /// This field is required.
    pub fn type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the data type. Valid value: <code>AWS:OpsItem</code>, <code>AWS:EC2InstanceInformation</code>, <code>AWS:OpsItemTrendline</code>, or <code>AWS:ComplianceSummary</code>.</p>
    pub fn set_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_name = input;
        self
    }
    /// <p>Name of the data type. Valid value: <code>AWS:OpsItem</code>, <code>AWS:EC2InstanceInformation</code>, <code>AWS:OpsItemTrendline</code>, or <code>AWS:ComplianceSummary</code>.</p>
    pub fn get_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_name
    }
    /// Consumes the builder and constructs a [`OpsResultAttribute`](crate::types::OpsResultAttribute).
    /// This method will fail if any of the following fields are not set:
    /// - [`type_name`](crate::types::builders::OpsResultAttributeBuilder::type_name)
    pub fn build(self) -> ::std::result::Result<crate::types::OpsResultAttribute, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OpsResultAttribute {
            type_name: self.type_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "type_name",
                    "type_name was not specified but it is required when building OpsResultAttribute",
                )
            })?,
        })
    }
}
