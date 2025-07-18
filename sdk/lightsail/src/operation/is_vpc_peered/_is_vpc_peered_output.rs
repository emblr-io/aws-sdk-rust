// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IsVpcPeeredOutput {
    /// <p>Returns <code>true</code> if the Lightsail VPC is peered; otherwise, <code>false</code>.</p>
    pub is_peered: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl IsVpcPeeredOutput {
    /// <p>Returns <code>true</code> if the Lightsail VPC is peered; otherwise, <code>false</code>.</p>
    pub fn is_peered(&self) -> ::std::option::Option<bool> {
        self.is_peered
    }
}
impl ::aws_types::request_id::RequestId for IsVpcPeeredOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl IsVpcPeeredOutput {
    /// Creates a new builder-style object to manufacture [`IsVpcPeeredOutput`](crate::operation::is_vpc_peered::IsVpcPeeredOutput).
    pub fn builder() -> crate::operation::is_vpc_peered::builders::IsVpcPeeredOutputBuilder {
        crate::operation::is_vpc_peered::builders::IsVpcPeeredOutputBuilder::default()
    }
}

/// A builder for [`IsVpcPeeredOutput`](crate::operation::is_vpc_peered::IsVpcPeeredOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IsVpcPeeredOutputBuilder {
    pub(crate) is_peered: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl IsVpcPeeredOutputBuilder {
    /// <p>Returns <code>true</code> if the Lightsail VPC is peered; otherwise, <code>false</code>.</p>
    pub fn is_peered(mut self, input: bool) -> Self {
        self.is_peered = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns <code>true</code> if the Lightsail VPC is peered; otherwise, <code>false</code>.</p>
    pub fn set_is_peered(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_peered = input;
        self
    }
    /// <p>Returns <code>true</code> if the Lightsail VPC is peered; otherwise, <code>false</code>.</p>
    pub fn get_is_peered(&self) -> &::std::option::Option<bool> {
        &self.is_peered
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`IsVpcPeeredOutput`](crate::operation::is_vpc_peered::IsVpcPeeredOutput).
    pub fn build(self) -> crate::operation::is_vpc_peered::IsVpcPeeredOutput {
        crate::operation::is_vpc_peered::IsVpcPeeredOutput {
            is_peered: self.is_peered,
            _request_id: self._request_id,
        }
    }
}
