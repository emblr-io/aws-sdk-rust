// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAssociatedRoute53HealthChecksInput {
    /// <p>The number of objects that you want to return with this call.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token that identifies which batch of results you want to see.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the routing control.</p>
    pub routing_control_arn: ::std::option::Option<::std::string::String>,
}
impl ListAssociatedRoute53HealthChecksInput {
    /// <p>The number of objects that you want to return with this call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token that identifies which batch of results you want to see.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the routing control.</p>
    pub fn routing_control_arn(&self) -> ::std::option::Option<&str> {
        self.routing_control_arn.as_deref()
    }
}
impl ListAssociatedRoute53HealthChecksInput {
    /// Creates a new builder-style object to manufacture [`ListAssociatedRoute53HealthChecksInput`](crate::operation::list_associated_route53_health_checks::ListAssociatedRoute53HealthChecksInput).
    pub fn builder() -> crate::operation::list_associated_route53_health_checks::builders::ListAssociatedRoute53HealthChecksInputBuilder {
        crate::operation::list_associated_route53_health_checks::builders::ListAssociatedRoute53HealthChecksInputBuilder::default()
    }
}

/// A builder for [`ListAssociatedRoute53HealthChecksInput`](crate::operation::list_associated_route53_health_checks::ListAssociatedRoute53HealthChecksInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAssociatedRoute53HealthChecksInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) routing_control_arn: ::std::option::Option<::std::string::String>,
}
impl ListAssociatedRoute53HealthChecksInputBuilder {
    /// <p>The number of objects that you want to return with this call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of objects that you want to return with this call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The number of objects that you want to return with this call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token that identifies which batch of results you want to see.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token that identifies which batch of results you want to see.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token that identifies which batch of results you want to see.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The Amazon Resource Name (ARN) of the routing control.</p>
    /// This field is required.
    pub fn routing_control_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.routing_control_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the routing control.</p>
    pub fn set_routing_control_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.routing_control_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the routing control.</p>
    pub fn get_routing_control_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.routing_control_arn
    }
    /// Consumes the builder and constructs a [`ListAssociatedRoute53HealthChecksInput`](crate::operation::list_associated_route53_health_checks::ListAssociatedRoute53HealthChecksInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_associated_route53_health_checks::ListAssociatedRoute53HealthChecksInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_associated_route53_health_checks::ListAssociatedRoute53HealthChecksInput {
                max_results: self.max_results,
                next_token: self.next_token,
                routing_control_arn: self.routing_control_arn,
            },
        )
    }
}
