// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCustomerGatewayAssociationsInput {
    /// <p>The ID of the global network.</p>
    pub global_network_id: ::std::option::Option<::std::string::String>,
    /// <p>One or more customer gateway Amazon Resource Names (ARNs). The maximum is 10.</p>
    pub customer_gateway_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The maximum number of results to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetCustomerGatewayAssociationsInput {
    /// <p>The ID of the global network.</p>
    pub fn global_network_id(&self) -> ::std::option::Option<&str> {
        self.global_network_id.as_deref()
    }
    /// <p>One or more customer gateway Amazon Resource Names (ARNs). The maximum is 10.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.customer_gateway_arns.is_none()`.
    pub fn customer_gateway_arns(&self) -> &[::std::string::String] {
        self.customer_gateway_arns.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetCustomerGatewayAssociationsInput {
    /// Creates a new builder-style object to manufacture [`GetCustomerGatewayAssociationsInput`](crate::operation::get_customer_gateway_associations::GetCustomerGatewayAssociationsInput).
    pub fn builder() -> crate::operation::get_customer_gateway_associations::builders::GetCustomerGatewayAssociationsInputBuilder {
        crate::operation::get_customer_gateway_associations::builders::GetCustomerGatewayAssociationsInputBuilder::default()
    }
}

/// A builder for [`GetCustomerGatewayAssociationsInput`](crate::operation::get_customer_gateway_associations::GetCustomerGatewayAssociationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCustomerGatewayAssociationsInputBuilder {
    pub(crate) global_network_id: ::std::option::Option<::std::string::String>,
    pub(crate) customer_gateway_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetCustomerGatewayAssociationsInputBuilder {
    /// <p>The ID of the global network.</p>
    /// This field is required.
    pub fn global_network_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.global_network_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the global network.</p>
    pub fn set_global_network_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.global_network_id = input;
        self
    }
    /// <p>The ID of the global network.</p>
    pub fn get_global_network_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.global_network_id
    }
    /// Appends an item to `customer_gateway_arns`.
    ///
    /// To override the contents of this collection use [`set_customer_gateway_arns`](Self::set_customer_gateway_arns).
    ///
    /// <p>One or more customer gateway Amazon Resource Names (ARNs). The maximum is 10.</p>
    pub fn customer_gateway_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.customer_gateway_arns.unwrap_or_default();
        v.push(input.into());
        self.customer_gateway_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more customer gateway Amazon Resource Names (ARNs). The maximum is 10.</p>
    pub fn set_customer_gateway_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.customer_gateway_arns = input;
        self
    }
    /// <p>One or more customer gateway Amazon Resource Names (ARNs). The maximum is 10.</p>
    pub fn get_customer_gateway_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.customer_gateway_arns
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetCustomerGatewayAssociationsInput`](crate::operation::get_customer_gateway_associations::GetCustomerGatewayAssociationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_customer_gateway_associations::GetCustomerGatewayAssociationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_customer_gateway_associations::GetCustomerGatewayAssociationsInput {
            global_network_id: self.global_network_id,
            customer_gateway_arns: self.customer_gateway_arns,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
