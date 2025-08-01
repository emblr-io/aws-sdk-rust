// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information of a test device. A thing ARN, certificate ARN or device role ARN is required.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeviceUnderTest {
    /// <p>Lists device's thing ARN.</p>
    pub thing_arn: ::std::option::Option<::std::string::String>,
    /// <p>Lists device's certificate ARN.</p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>Lists device's role ARN.</p>
    pub device_role_arn: ::std::option::Option<::std::string::String>,
}
impl DeviceUnderTest {
    /// <p>Lists device's thing ARN.</p>
    pub fn thing_arn(&self) -> ::std::option::Option<&str> {
        self.thing_arn.as_deref()
    }
    /// <p>Lists device's certificate ARN.</p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
    /// <p>Lists device's role ARN.</p>
    pub fn device_role_arn(&self) -> ::std::option::Option<&str> {
        self.device_role_arn.as_deref()
    }
}
impl DeviceUnderTest {
    /// Creates a new builder-style object to manufacture [`DeviceUnderTest`](crate::types::DeviceUnderTest).
    pub fn builder() -> crate::types::builders::DeviceUnderTestBuilder {
        crate::types::builders::DeviceUnderTestBuilder::default()
    }
}

/// A builder for [`DeviceUnderTest`](crate::types::DeviceUnderTest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeviceUnderTestBuilder {
    pub(crate) thing_arn: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) device_role_arn: ::std::option::Option<::std::string::String>,
}
impl DeviceUnderTestBuilder {
    /// <p>Lists device's thing ARN.</p>
    pub fn thing_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Lists device's thing ARN.</p>
    pub fn set_thing_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_arn = input;
        self
    }
    /// <p>Lists device's thing ARN.</p>
    pub fn get_thing_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_arn
    }
    /// <p>Lists device's certificate ARN.</p>
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Lists device's certificate ARN.</p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>Lists device's certificate ARN.</p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// <p>Lists device's role ARN.</p>
    pub fn device_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Lists device's role ARN.</p>
    pub fn set_device_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_role_arn = input;
        self
    }
    /// <p>Lists device's role ARN.</p>
    pub fn get_device_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_role_arn
    }
    /// Consumes the builder and constructs a [`DeviceUnderTest`](crate::types::DeviceUnderTest).
    pub fn build(self) -> crate::types::DeviceUnderTest {
        crate::types::DeviceUnderTest {
            thing_arn: self.thing_arn,
            certificate_arn: self.certificate_arn,
            device_role_arn: self.device_role_arn,
        }
    }
}
