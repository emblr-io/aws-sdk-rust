// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyVpcEndpointServicePayerResponsibilityInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The ID of the service.</p>
    pub service_id: ::std::option::Option<::std::string::String>,
    /// <p>The entity that is responsible for the endpoint costs. The default is the endpoint owner. If you set the payer responsibility to the service owner, you cannot set it back to the endpoint owner.</p>
    pub payer_responsibility: ::std::option::Option<crate::types::PayerResponsibility>,
}
impl ModifyVpcEndpointServicePayerResponsibilityInput {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The ID of the service.</p>
    pub fn service_id(&self) -> ::std::option::Option<&str> {
        self.service_id.as_deref()
    }
    /// <p>The entity that is responsible for the endpoint costs. The default is the endpoint owner. If you set the payer responsibility to the service owner, you cannot set it back to the endpoint owner.</p>
    pub fn payer_responsibility(&self) -> ::std::option::Option<&crate::types::PayerResponsibility> {
        self.payer_responsibility.as_ref()
    }
}
impl ModifyVpcEndpointServicePayerResponsibilityInput {
    /// Creates a new builder-style object to manufacture [`ModifyVpcEndpointServicePayerResponsibilityInput`](crate::operation::modify_vpc_endpoint_service_payer_responsibility::ModifyVpcEndpointServicePayerResponsibilityInput).
    pub fn builder(
    ) -> crate::operation::modify_vpc_endpoint_service_payer_responsibility::builders::ModifyVpcEndpointServicePayerResponsibilityInputBuilder {
        crate::operation::modify_vpc_endpoint_service_payer_responsibility::builders::ModifyVpcEndpointServicePayerResponsibilityInputBuilder::default(
        )
    }
}

/// A builder for [`ModifyVpcEndpointServicePayerResponsibilityInput`](crate::operation::modify_vpc_endpoint_service_payer_responsibility::ModifyVpcEndpointServicePayerResponsibilityInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyVpcEndpointServicePayerResponsibilityInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) service_id: ::std::option::Option<::std::string::String>,
    pub(crate) payer_responsibility: ::std::option::Option<crate::types::PayerResponsibility>,
}
impl ModifyVpcEndpointServicePayerResponsibilityInputBuilder {
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>The ID of the service.</p>
    /// This field is required.
    pub fn service_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the service.</p>
    pub fn set_service_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_id = input;
        self
    }
    /// <p>The ID of the service.</p>
    pub fn get_service_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_id
    }
    /// <p>The entity that is responsible for the endpoint costs. The default is the endpoint owner. If you set the payer responsibility to the service owner, you cannot set it back to the endpoint owner.</p>
    /// This field is required.
    pub fn payer_responsibility(mut self, input: crate::types::PayerResponsibility) -> Self {
        self.payer_responsibility = ::std::option::Option::Some(input);
        self
    }
    /// <p>The entity that is responsible for the endpoint costs. The default is the endpoint owner. If you set the payer responsibility to the service owner, you cannot set it back to the endpoint owner.</p>
    pub fn set_payer_responsibility(mut self, input: ::std::option::Option<crate::types::PayerResponsibility>) -> Self {
        self.payer_responsibility = input;
        self
    }
    /// <p>The entity that is responsible for the endpoint costs. The default is the endpoint owner. If you set the payer responsibility to the service owner, you cannot set it back to the endpoint owner.</p>
    pub fn get_payer_responsibility(&self) -> &::std::option::Option<crate::types::PayerResponsibility> {
        &self.payer_responsibility
    }
    /// Consumes the builder and constructs a [`ModifyVpcEndpointServicePayerResponsibilityInput`](crate::operation::modify_vpc_endpoint_service_payer_responsibility::ModifyVpcEndpointServicePayerResponsibilityInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_vpc_endpoint_service_payer_responsibility::ModifyVpcEndpointServicePayerResponsibilityInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::modify_vpc_endpoint_service_payer_responsibility::ModifyVpcEndpointServicePayerResponsibilityInput {
                dry_run: self.dry_run,
                service_id: self.service_id,
                payer_responsibility: self.payer_responsibility,
            },
        )
    }
}
