// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SearchInput {
    /// <p>A string that includes keywords and filters that specify the resources that you want to include in the results.</p>
    /// <p>For the complete syntax supported by the <code>QueryString</code> parameter, see <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html">Search query syntax reference for Resource Explorer</a>.</p>
    /// <p>The search is completely case insensitive. You can specify an empty string to return all results up to the limit of 1,000 total results.</p><note>
    /// <p>The operation can return only the first 1,000 results. If the resource you want is not included, then use a different value for <code>QueryString</code> to refine the results.</p>
    /// </note>
    pub query_string: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results that you want included on each page of the response. If you do not include this parameter, it defaults to a value appropriate to the operation. If additional items exist beyond those included in the current response, the <code>NextToken</code> response element is present and has a value (is not null). Include that value as the <code>NextToken</code> request parameter in the next call to the operation to get the next part of the results.</p><note>
    /// <p>An API operation can return fewer results than the maximum even when there are more results available. You should check <code>NextToken</code> after every operation to ensure that you receive all of the results.</p>
    /// </note>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of the view to use for the query. If you don't specify a value for this parameter, then the operation automatically uses the default view for the Amazon Web Services Region in which you called this operation. If the Region either doesn't have a default view or if you don't have permission to use the default view, then the operation fails with a <code>401 Unauthorized</code> exception.</p>
    pub view_arn: ::std::option::Option<::std::string::String>,
    /// <p>The parameter for receiving additional results if you receive a <code>NextToken</code> response in a previous request. A <code>NextToken</code> response indicates that more output is available. Set this parameter to the value of the previous call's <code>NextToken</code> response to indicate where the output should continue from. The pagination tokens expire after 24 hours.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl SearchInput {
    /// <p>A string that includes keywords and filters that specify the resources that you want to include in the results.</p>
    /// <p>For the complete syntax supported by the <code>QueryString</code> parameter, see <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html">Search query syntax reference for Resource Explorer</a>.</p>
    /// <p>The search is completely case insensitive. You can specify an empty string to return all results up to the limit of 1,000 total results.</p><note>
    /// <p>The operation can return only the first 1,000 results. If the resource you want is not included, then use a different value for <code>QueryString</code> to refine the results.</p>
    /// </note>
    pub fn query_string(&self) -> ::std::option::Option<&str> {
        self.query_string.as_deref()
    }
    /// <p>The maximum number of results that you want included on each page of the response. If you do not include this parameter, it defaults to a value appropriate to the operation. If additional items exist beyond those included in the current response, the <code>NextToken</code> response element is present and has a value (is not null). Include that value as the <code>NextToken</code> request parameter in the next call to the operation to get the next part of the results.</p><note>
    /// <p>An API operation can return fewer results than the maximum even when there are more results available. You should check <code>NextToken</code> after every operation to ensure that you receive all of the results.</p>
    /// </note>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of the view to use for the query. If you don't specify a value for this parameter, then the operation automatically uses the default view for the Amazon Web Services Region in which you called this operation. If the Region either doesn't have a default view or if you don't have permission to use the default view, then the operation fails with a <code>401 Unauthorized</code> exception.</p>
    pub fn view_arn(&self) -> ::std::option::Option<&str> {
        self.view_arn.as_deref()
    }
    /// <p>The parameter for receiving additional results if you receive a <code>NextToken</code> response in a previous request. A <code>NextToken</code> response indicates that more output is available. Set this parameter to the value of the previous call's <code>NextToken</code> response to indicate where the output should continue from. The pagination tokens expire after 24 hours.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::std::fmt::Debug for SearchInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SearchInput");
        formatter.field("query_string", &"*** Sensitive Data Redacted ***");
        formatter.field("max_results", &self.max_results);
        formatter.field("view_arn", &self.view_arn);
        formatter.field("next_token", &self.next_token);
        formatter.finish()
    }
}
impl SearchInput {
    /// Creates a new builder-style object to manufacture [`SearchInput`](crate::operation::search::SearchInput).
    pub fn builder() -> crate::operation::search::builders::SearchInputBuilder {
        crate::operation::search::builders::SearchInputBuilder::default()
    }
}

/// A builder for [`SearchInput`](crate::operation::search::SearchInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SearchInputBuilder {
    pub(crate) query_string: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) view_arn: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl SearchInputBuilder {
    /// <p>A string that includes keywords and filters that specify the resources that you want to include in the results.</p>
    /// <p>For the complete syntax supported by the <code>QueryString</code> parameter, see <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html">Search query syntax reference for Resource Explorer</a>.</p>
    /// <p>The search is completely case insensitive. You can specify an empty string to return all results up to the limit of 1,000 total results.</p><note>
    /// <p>The operation can return only the first 1,000 results. If the resource you want is not included, then use a different value for <code>QueryString</code> to refine the results.</p>
    /// </note>
    /// This field is required.
    pub fn query_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that includes keywords and filters that specify the resources that you want to include in the results.</p>
    /// <p>For the complete syntax supported by the <code>QueryString</code> parameter, see <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html">Search query syntax reference for Resource Explorer</a>.</p>
    /// <p>The search is completely case insensitive. You can specify an empty string to return all results up to the limit of 1,000 total results.</p><note>
    /// <p>The operation can return only the first 1,000 results. If the resource you want is not included, then use a different value for <code>QueryString</code> to refine the results.</p>
    /// </note>
    pub fn set_query_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_string = input;
        self
    }
    /// <p>A string that includes keywords and filters that specify the resources that you want to include in the results.</p>
    /// <p>For the complete syntax supported by the <code>QueryString</code> parameter, see <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html">Search query syntax reference for Resource Explorer</a>.</p>
    /// <p>The search is completely case insensitive. You can specify an empty string to return all results up to the limit of 1,000 total results.</p><note>
    /// <p>The operation can return only the first 1,000 results. If the resource you want is not included, then use a different value for <code>QueryString</code> to refine the results.</p>
    /// </note>
    pub fn get_query_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_string
    }
    /// <p>The maximum number of results that you want included on each page of the response. If you do not include this parameter, it defaults to a value appropriate to the operation. If additional items exist beyond those included in the current response, the <code>NextToken</code> response element is present and has a value (is not null). Include that value as the <code>NextToken</code> request parameter in the next call to the operation to get the next part of the results.</p><note>
    /// <p>An API operation can return fewer results than the maximum even when there are more results available. You should check <code>NextToken</code> after every operation to ensure that you receive all of the results.</p>
    /// </note>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results that you want included on each page of the response. If you do not include this parameter, it defaults to a value appropriate to the operation. If additional items exist beyond those included in the current response, the <code>NextToken</code> response element is present and has a value (is not null). Include that value as the <code>NextToken</code> request parameter in the next call to the operation to get the next part of the results.</p><note>
    /// <p>An API operation can return fewer results than the maximum even when there are more results available. You should check <code>NextToken</code> after every operation to ensure that you receive all of the results.</p>
    /// </note>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results that you want included on each page of the response. If you do not include this parameter, it defaults to a value appropriate to the operation. If additional items exist beyond those included in the current response, the <code>NextToken</code> response element is present and has a value (is not null). Include that value as the <code>NextToken</code> request parameter in the next call to the operation to get the next part of the results.</p><note>
    /// <p>An API operation can return fewer results than the maximum even when there are more results available. You should check <code>NextToken</code> after every operation to ensure that you receive all of the results.</p>
    /// </note>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of the view to use for the query. If you don't specify a value for this parameter, then the operation automatically uses the default view for the Amazon Web Services Region in which you called this operation. If the Region either doesn't have a default view or if you don't have permission to use the default view, then the operation fails with a <code>401 Unauthorized</code> exception.</p>
    pub fn view_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.view_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of the view to use for the query. If you don't specify a value for this parameter, then the operation automatically uses the default view for the Amazon Web Services Region in which you called this operation. If the Region either doesn't have a default view or if you don't have permission to use the default view, then the operation fails with a <code>401 Unauthorized</code> exception.</p>
    pub fn set_view_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.view_arn = input;
        self
    }
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of the view to use for the query. If you don't specify a value for this parameter, then the operation automatically uses the default view for the Amazon Web Services Region in which you called this operation. If the Region either doesn't have a default view or if you don't have permission to use the default view, then the operation fails with a <code>401 Unauthorized</code> exception.</p>
    pub fn get_view_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.view_arn
    }
    /// <p>The parameter for receiving additional results if you receive a <code>NextToken</code> response in a previous request. A <code>NextToken</code> response indicates that more output is available. Set this parameter to the value of the previous call's <code>NextToken</code> response to indicate where the output should continue from. The pagination tokens expire after 24 hours.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The parameter for receiving additional results if you receive a <code>NextToken</code> response in a previous request. A <code>NextToken</code> response indicates that more output is available. Set this parameter to the value of the previous call's <code>NextToken</code> response to indicate where the output should continue from. The pagination tokens expire after 24 hours.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The parameter for receiving additional results if you receive a <code>NextToken</code> response in a previous request. A <code>NextToken</code> response indicates that more output is available. Set this parameter to the value of the previous call's <code>NextToken</code> response to indicate where the output should continue from. The pagination tokens expire after 24 hours.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`SearchInput`](crate::operation::search::SearchInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::search::SearchInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::search::SearchInput {
            query_string: self.query_string,
            max_results: self.max_results,
            view_arn: self.view_arn,
            next_token: self.next_token,
        })
    }
}
impl ::std::fmt::Debug for SearchInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SearchInputBuilder");
        formatter.field("query_string", &"*** Sensitive Data Redacted ***");
        formatter.field("max_results", &self.max_results);
        formatter.field("view_arn", &self.view_arn);
        formatter.field("next_token", &self.next_token);
        formatter.finish()
    }
}
