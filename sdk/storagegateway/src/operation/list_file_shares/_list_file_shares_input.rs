// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>ListFileShareInput</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFileSharesInput {
    /// <p>The Amazon Resource Name (ARN) of the gateway whose file shares you want to list. If this field is not present, all file shares under your account are listed.</p>
    pub gateway_arn: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of file shares to return in the response. The value must be an integer with a value greater than zero. Optional.</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>Opaque pagination token returned from a previous ListFileShares operation. If present, <code>Marker</code> specifies where to continue the list from after a previous call to ListFileShares. Optional.</p>
    pub marker: ::std::option::Option<::std::string::String>,
}
impl ListFileSharesInput {
    /// <p>The Amazon Resource Name (ARN) of the gateway whose file shares you want to list. If this field is not present, all file shares under your account are listed.</p>
    pub fn gateway_arn(&self) -> ::std::option::Option<&str> {
        self.gateway_arn.as_deref()
    }
    /// <p>The maximum number of file shares to return in the response. The value must be an integer with a value greater than zero. Optional.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>Opaque pagination token returned from a previous ListFileShares operation. If present, <code>Marker</code> specifies where to continue the list from after a previous call to ListFileShares. Optional.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ListFileSharesInput {
    /// Creates a new builder-style object to manufacture [`ListFileSharesInput`](crate::operation::list_file_shares::ListFileSharesInput).
    pub fn builder() -> crate::operation::list_file_shares::builders::ListFileSharesInputBuilder {
        crate::operation::list_file_shares::builders::ListFileSharesInputBuilder::default()
    }
}

/// A builder for [`ListFileSharesInput`](crate::operation::list_file_shares::ListFileSharesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFileSharesInputBuilder {
    pub(crate) gateway_arn: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
}
impl ListFileSharesInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the gateway whose file shares you want to list. If this field is not present, all file shares under your account are listed.</p>
    pub fn gateway_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway whose file shares you want to list. If this field is not present, all file shares under your account are listed.</p>
    pub fn set_gateway_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway whose file shares you want to list. If this field is not present, all file shares under your account are listed.</p>
    pub fn get_gateway_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_arn
    }
    /// <p>The maximum number of file shares to return in the response. The value must be an integer with a value greater than zero. Optional.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of file shares to return in the response. The value must be an integer with a value greater than zero. Optional.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of file shares to return in the response. The value must be an integer with a value greater than zero. Optional.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// <p>Opaque pagination token returned from a previous ListFileShares operation. If present, <code>Marker</code> specifies where to continue the list from after a previous call to ListFileShares. Optional.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Opaque pagination token returned from a previous ListFileShares operation. If present, <code>Marker</code> specifies where to continue the list from after a previous call to ListFileShares. Optional.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>Opaque pagination token returned from a previous ListFileShares operation. If present, <code>Marker</code> specifies where to continue the list from after a previous call to ListFileShares. Optional.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Consumes the builder and constructs a [`ListFileSharesInput`](crate::operation::list_file_shares::ListFileSharesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_file_shares::ListFileSharesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_file_shares::ListFileSharesInput {
            gateway_arn: self.gateway_arn,
            limit: self.limit,
            marker: self.marker,
        })
    }
}
