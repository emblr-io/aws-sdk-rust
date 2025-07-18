// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteVpcConnectionOutput {
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies an MSK VPC connection.</p>
    pub vpc_connection_arn: ::std::option::Option<::std::string::String>,
    /// <p>The state of the VPC connection.</p>
    pub state: ::std::option::Option<crate::types::VpcConnectionState>,
    _request_id: Option<String>,
}
impl DeleteVpcConnectionOutput {
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies an MSK VPC connection.</p>
    pub fn vpc_connection_arn(&self) -> ::std::option::Option<&str> {
        self.vpc_connection_arn.as_deref()
    }
    /// <p>The state of the VPC connection.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::VpcConnectionState> {
        self.state.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteVpcConnectionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteVpcConnectionOutput {
    /// Creates a new builder-style object to manufacture [`DeleteVpcConnectionOutput`](crate::operation::delete_vpc_connection::DeleteVpcConnectionOutput).
    pub fn builder() -> crate::operation::delete_vpc_connection::builders::DeleteVpcConnectionOutputBuilder {
        crate::operation::delete_vpc_connection::builders::DeleteVpcConnectionOutputBuilder::default()
    }
}

/// A builder for [`DeleteVpcConnectionOutput`](crate::operation::delete_vpc_connection::DeleteVpcConnectionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteVpcConnectionOutputBuilder {
    pub(crate) vpc_connection_arn: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::VpcConnectionState>,
    _request_id: Option<String>,
}
impl DeleteVpcConnectionOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies an MSK VPC connection.</p>
    pub fn vpc_connection_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_connection_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies an MSK VPC connection.</p>
    pub fn set_vpc_connection_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_connection_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies an MSK VPC connection.</p>
    pub fn get_vpc_connection_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_connection_arn
    }
    /// <p>The state of the VPC connection.</p>
    pub fn state(mut self, input: crate::types::VpcConnectionState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the VPC connection.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::VpcConnectionState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the VPC connection.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::VpcConnectionState> {
        &self.state
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteVpcConnectionOutput`](crate::operation::delete_vpc_connection::DeleteVpcConnectionOutput).
    pub fn build(self) -> crate::operation::delete_vpc_connection::DeleteVpcConnectionOutput {
        crate::operation::delete_vpc_connection::DeleteVpcConnectionOutput {
            vpc_connection_arn: self.vpc_connection_arn,
            state: self.state,
            _request_id: self._request_id,
        }
    }
}
