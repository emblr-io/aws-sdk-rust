// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResourceGroupingRecommendationsInput {
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub app_arn: ::std::option::Option<::std::string::String>,
    /// <p>Null, or the token from a previous call to get the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of grouping recommendations to be displayed per Resilience Hub application.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListResourceGroupingRecommendationsInput {
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn app_arn(&self) -> ::std::option::Option<&str> {
        self.app_arn.as_deref()
    }
    /// <p>Null, or the token from a previous call to get the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Maximum number of grouping recommendations to be displayed per Resilience Hub application.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListResourceGroupingRecommendationsInput {
    /// Creates a new builder-style object to manufacture [`ListResourceGroupingRecommendationsInput`](crate::operation::list_resource_grouping_recommendations::ListResourceGroupingRecommendationsInput).
    pub fn builder() -> crate::operation::list_resource_grouping_recommendations::builders::ListResourceGroupingRecommendationsInputBuilder {
        crate::operation::list_resource_grouping_recommendations::builders::ListResourceGroupingRecommendationsInputBuilder::default()
    }
}

/// A builder for [`ListResourceGroupingRecommendationsInput`](crate::operation::list_resource_grouping_recommendations::ListResourceGroupingRecommendationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResourceGroupingRecommendationsInputBuilder {
    pub(crate) app_arn: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListResourceGroupingRecommendationsInputBuilder {
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn app_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn set_app_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn get_app_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_arn
    }
    /// <p>Null, or the token from a previous call to get the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Null, or the token from a previous call to get the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Null, or the token from a previous call to get the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Maximum number of grouping recommendations to be displayed per Resilience Hub application.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of grouping recommendations to be displayed per Resilience Hub application.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of grouping recommendations to be displayed per Resilience Hub application.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListResourceGroupingRecommendationsInput`](crate::operation::list_resource_grouping_recommendations::ListResourceGroupingRecommendationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_resource_grouping_recommendations::ListResourceGroupingRecommendationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_resource_grouping_recommendations::ListResourceGroupingRecommendationsInput {
                app_arn: self.app_arn,
                next_token: self.next_token,
                max_results: self.max_results,
            },
        )
    }
}
