// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An activity that adds information from the IoT Device Shadow service to a message.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeviceShadowEnrichActivity {
    /// <p>The name of the <code>deviceShadowEnrich</code> activity.</p>
    pub name: ::std::string::String,
    /// <p>The name of the attribute that is added to the message.</p>
    pub attribute: ::std::string::String,
    /// <p>The name of the IoT device whose shadow information is added to the message.</p>
    pub thing_name: ::std::string::String,
    /// <p>The ARN of the role that allows access to the device's shadow.</p>
    pub role_arn: ::std::string::String,
    /// <p>The next activity in the pipeline.</p>
    pub next: ::std::option::Option<::std::string::String>,
}
impl DeviceShadowEnrichActivity {
    /// <p>The name of the <code>deviceShadowEnrich</code> activity.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The name of the attribute that is added to the message.</p>
    pub fn attribute(&self) -> &str {
        use std::ops::Deref;
        self.attribute.deref()
    }
    /// <p>The name of the IoT device whose shadow information is added to the message.</p>
    pub fn thing_name(&self) -> &str {
        use std::ops::Deref;
        self.thing_name.deref()
    }
    /// <p>The ARN of the role that allows access to the device's shadow.</p>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
    /// <p>The next activity in the pipeline.</p>
    pub fn next(&self) -> ::std::option::Option<&str> {
        self.next.as_deref()
    }
}
impl DeviceShadowEnrichActivity {
    /// Creates a new builder-style object to manufacture [`DeviceShadowEnrichActivity`](crate::types::DeviceShadowEnrichActivity).
    pub fn builder() -> crate::types::builders::DeviceShadowEnrichActivityBuilder {
        crate::types::builders::DeviceShadowEnrichActivityBuilder::default()
    }
}

/// A builder for [`DeviceShadowEnrichActivity`](crate::types::DeviceShadowEnrichActivity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeviceShadowEnrichActivityBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) attribute: ::std::option::Option<::std::string::String>,
    pub(crate) thing_name: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) next: ::std::option::Option<::std::string::String>,
}
impl DeviceShadowEnrichActivityBuilder {
    /// <p>The name of the <code>deviceShadowEnrich</code> activity.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the <code>deviceShadowEnrich</code> activity.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the <code>deviceShadowEnrich</code> activity.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The name of the attribute that is added to the message.</p>
    /// This field is required.
    pub fn attribute(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attribute = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the attribute that is added to the message.</p>
    pub fn set_attribute(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attribute = input;
        self
    }
    /// <p>The name of the attribute that is added to the message.</p>
    pub fn get_attribute(&self) -> &::std::option::Option<::std::string::String> {
        &self.attribute
    }
    /// <p>The name of the IoT device whose shadow information is added to the message.</p>
    /// This field is required.
    pub fn thing_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the IoT device whose shadow information is added to the message.</p>
    pub fn set_thing_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_name = input;
        self
    }
    /// <p>The name of the IoT device whose shadow information is added to the message.</p>
    pub fn get_thing_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_name
    }
    /// <p>The ARN of the role that allows access to the device's shadow.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the role that allows access to the device's shadow.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The ARN of the role that allows access to the device's shadow.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The next activity in the pipeline.</p>
    pub fn next(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next activity in the pipeline.</p>
    pub fn set_next(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next = input;
        self
    }
    /// <p>The next activity in the pipeline.</p>
    pub fn get_next(&self) -> &::std::option::Option<::std::string::String> {
        &self.next
    }
    /// Consumes the builder and constructs a [`DeviceShadowEnrichActivity`](crate::types::DeviceShadowEnrichActivity).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::DeviceShadowEnrichActivityBuilder::name)
    /// - [`attribute`](crate::types::builders::DeviceShadowEnrichActivityBuilder::attribute)
    /// - [`thing_name`](crate::types::builders::DeviceShadowEnrichActivityBuilder::thing_name)
    /// - [`role_arn`](crate::types::builders::DeviceShadowEnrichActivityBuilder::role_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::DeviceShadowEnrichActivity, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DeviceShadowEnrichActivity {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building DeviceShadowEnrichActivity",
                )
            })?,
            attribute: self.attribute.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attribute",
                    "attribute was not specified but it is required when building DeviceShadowEnrichActivity",
                )
            })?,
            thing_name: self.thing_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "thing_name",
                    "thing_name was not specified but it is required when building DeviceShadowEnrichActivity",
                )
            })?,
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building DeviceShadowEnrichActivity",
                )
            })?,
            next: self.next,
        })
    }
}
