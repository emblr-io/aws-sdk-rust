// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateApplicationFleetInput {
    /// <p>The name of the fleet.</p>
    pub fleet_name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the application.</p>
    pub application_arn: ::std::option::Option<::std::string::String>,
}
impl DisassociateApplicationFleetInput {
    /// <p>The name of the fleet.</p>
    pub fn fleet_name(&self) -> ::std::option::Option<&str> {
        self.fleet_name.as_deref()
    }
    /// <p>The ARN of the application.</p>
    pub fn application_arn(&self) -> ::std::option::Option<&str> {
        self.application_arn.as_deref()
    }
}
impl DisassociateApplicationFleetInput {
    /// Creates a new builder-style object to manufacture [`DisassociateApplicationFleetInput`](crate::operation::disassociate_application_fleet::DisassociateApplicationFleetInput).
    pub fn builder() -> crate::operation::disassociate_application_fleet::builders::DisassociateApplicationFleetInputBuilder {
        crate::operation::disassociate_application_fleet::builders::DisassociateApplicationFleetInputBuilder::default()
    }
}

/// A builder for [`DisassociateApplicationFleetInput`](crate::operation::disassociate_application_fleet::DisassociateApplicationFleetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateApplicationFleetInputBuilder {
    pub(crate) fleet_name: ::std::option::Option<::std::string::String>,
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
}
impl DisassociateApplicationFleetInputBuilder {
    /// <p>The name of the fleet.</p>
    /// This field is required.
    pub fn fleet_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the fleet.</p>
    pub fn set_fleet_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet_name = input;
        self
    }
    /// <p>The name of the fleet.</p>
    pub fn get_fleet_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet_name
    }
    /// <p>The ARN of the application.</p>
    /// This field is required.
    pub fn application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the application.</p>
    pub fn set_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_arn = input;
        self
    }
    /// <p>The ARN of the application.</p>
    pub fn get_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_arn
    }
    /// Consumes the builder and constructs a [`DisassociateApplicationFleetInput`](crate::operation::disassociate_application_fleet::DisassociateApplicationFleetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_application_fleet::DisassociateApplicationFleetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::disassociate_application_fleet::DisassociateApplicationFleetInput {
            fleet_name: self.fleet_name,
            application_arn: self.application_arn,
        })
    }
}
