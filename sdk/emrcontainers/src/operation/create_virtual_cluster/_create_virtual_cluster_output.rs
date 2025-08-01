// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateVirtualClusterOutput {
    /// <p>This output contains the virtual cluster ID.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>This output contains the name of the virtual cluster.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>This output contains the ARN of virtual cluster.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateVirtualClusterOutput {
    /// <p>This output contains the virtual cluster ID.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>This output contains the name of the virtual cluster.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>This output contains the ARN of virtual cluster.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateVirtualClusterOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateVirtualClusterOutput {
    /// Creates a new builder-style object to manufacture [`CreateVirtualClusterOutput`](crate::operation::create_virtual_cluster::CreateVirtualClusterOutput).
    pub fn builder() -> crate::operation::create_virtual_cluster::builders::CreateVirtualClusterOutputBuilder {
        crate::operation::create_virtual_cluster::builders::CreateVirtualClusterOutputBuilder::default()
    }
}

/// A builder for [`CreateVirtualClusterOutput`](crate::operation::create_virtual_cluster::CreateVirtualClusterOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateVirtualClusterOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateVirtualClusterOutputBuilder {
    /// <p>This output contains the virtual cluster ID.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This output contains the virtual cluster ID.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>This output contains the virtual cluster ID.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>This output contains the name of the virtual cluster.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This output contains the name of the virtual cluster.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>This output contains the name of the virtual cluster.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>This output contains the ARN of virtual cluster.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This output contains the ARN of virtual cluster.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>This output contains the ARN of virtual cluster.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateVirtualClusterOutput`](crate::operation::create_virtual_cluster::CreateVirtualClusterOutput).
    pub fn build(self) -> crate::operation::create_virtual_cluster::CreateVirtualClusterOutput {
        crate::operation::create_virtual_cluster::CreateVirtualClusterOutput {
            id: self.id,
            name: self.name,
            arn: self.arn,
            _request_id: self._request_id,
        }
    }
}
