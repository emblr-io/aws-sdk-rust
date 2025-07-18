// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOutpostSupportedInstanceTypesInput {
    /// <p>The ID or ARN of the Outpost.</p>
    pub outpost_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the Amazon Web Services Outposts order.</p>
    pub order_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Outpost asset. An Outpost asset can be a single server within an Outposts rack or an Outposts server configuration.</p>
    pub asset_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum page size.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The pagination token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetOutpostSupportedInstanceTypesInput {
    /// <p>The ID or ARN of the Outpost.</p>
    pub fn outpost_identifier(&self) -> ::std::option::Option<&str> {
        self.outpost_identifier.as_deref()
    }
    /// <p>The ID for the Amazon Web Services Outposts order.</p>
    pub fn order_id(&self) -> ::std::option::Option<&str> {
        self.order_id.as_deref()
    }
    /// <p>The ID of the Outpost asset. An Outpost asset can be a single server within an Outposts rack or an Outposts server configuration.</p>
    pub fn asset_id(&self) -> ::std::option::Option<&str> {
        self.asset_id.as_deref()
    }
    /// <p>The maximum page size.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The pagination token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetOutpostSupportedInstanceTypesInput {
    /// Creates a new builder-style object to manufacture [`GetOutpostSupportedInstanceTypesInput`](crate::operation::get_outpost_supported_instance_types::GetOutpostSupportedInstanceTypesInput).
    pub fn builder() -> crate::operation::get_outpost_supported_instance_types::builders::GetOutpostSupportedInstanceTypesInputBuilder {
        crate::operation::get_outpost_supported_instance_types::builders::GetOutpostSupportedInstanceTypesInputBuilder::default()
    }
}

/// A builder for [`GetOutpostSupportedInstanceTypesInput`](crate::operation::get_outpost_supported_instance_types::GetOutpostSupportedInstanceTypesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOutpostSupportedInstanceTypesInputBuilder {
    pub(crate) outpost_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) order_id: ::std::option::Option<::std::string::String>,
    pub(crate) asset_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetOutpostSupportedInstanceTypesInputBuilder {
    /// <p>The ID or ARN of the Outpost.</p>
    /// This field is required.
    pub fn outpost_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.outpost_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID or ARN of the Outpost.</p>
    pub fn set_outpost_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.outpost_identifier = input;
        self
    }
    /// <p>The ID or ARN of the Outpost.</p>
    pub fn get_outpost_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.outpost_identifier
    }
    /// <p>The ID for the Amazon Web Services Outposts order.</p>
    pub fn order_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.order_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the Amazon Web Services Outposts order.</p>
    pub fn set_order_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.order_id = input;
        self
    }
    /// <p>The ID for the Amazon Web Services Outposts order.</p>
    pub fn get_order_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.order_id
    }
    /// <p>The ID of the Outpost asset. An Outpost asset can be a single server within an Outposts rack or an Outposts server configuration.</p>
    pub fn asset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.asset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Outpost asset. An Outpost asset can be a single server within an Outposts rack or an Outposts server configuration.</p>
    pub fn set_asset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.asset_id = input;
        self
    }
    /// <p>The ID of the Outpost asset. An Outpost asset can be a single server within an Outposts rack or an Outposts server configuration.</p>
    pub fn get_asset_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.asset_id
    }
    /// <p>The maximum page size.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum page size.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum page size.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The pagination token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetOutpostSupportedInstanceTypesInput`](crate::operation::get_outpost_supported_instance_types::GetOutpostSupportedInstanceTypesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_outpost_supported_instance_types::GetOutpostSupportedInstanceTypesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_outpost_supported_instance_types::GetOutpostSupportedInstanceTypesInput {
                outpost_identifier: self.outpost_identifier,
                order_id: self.order_id,
                asset_id: self.asset_id,
                max_results: self.max_results,
                next_token: self.next_token,
            },
        )
    }
}
