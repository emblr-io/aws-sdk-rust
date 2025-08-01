// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResolverRulesOutput {
    /// <p>If more than <code>MaxResults</code> Resolver rules match the specified criteria, you can submit another <code>ListResolverRules</code> request to get the next group of results. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The value that you specified for <code>MaxResults</code> in the request.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The Resolver rules that were created using the current Amazon Web Services account and that match the specified filters, if any.</p>
    pub resolver_rules: ::std::option::Option<::std::vec::Vec<crate::types::ResolverRule>>,
    _request_id: Option<String>,
}
impl ListResolverRulesOutput {
    /// <p>If more than <code>MaxResults</code> Resolver rules match the specified criteria, you can submit another <code>ListResolverRules</code> request to get the next group of results. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The value that you specified for <code>MaxResults</code> in the request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The Resolver rules that were created using the current Amazon Web Services account and that match the specified filters, if any.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resolver_rules.is_none()`.
    pub fn resolver_rules(&self) -> &[crate::types::ResolverRule] {
        self.resolver_rules.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListResolverRulesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListResolverRulesOutput {
    /// Creates a new builder-style object to manufacture [`ListResolverRulesOutput`](crate::operation::list_resolver_rules::ListResolverRulesOutput).
    pub fn builder() -> crate::operation::list_resolver_rules::builders::ListResolverRulesOutputBuilder {
        crate::operation::list_resolver_rules::builders::ListResolverRulesOutputBuilder::default()
    }
}

/// A builder for [`ListResolverRulesOutput`](crate::operation::list_resolver_rules::ListResolverRulesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResolverRulesOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) resolver_rules: ::std::option::Option<::std::vec::Vec<crate::types::ResolverRule>>,
    _request_id: Option<String>,
}
impl ListResolverRulesOutputBuilder {
    /// <p>If more than <code>MaxResults</code> Resolver rules match the specified criteria, you can submit another <code>ListResolverRules</code> request to get the next group of results. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If more than <code>MaxResults</code> Resolver rules match the specified criteria, you can submit another <code>ListResolverRules</code> request to get the next group of results. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If more than <code>MaxResults</code> Resolver rules match the specified criteria, you can submit another <code>ListResolverRules</code> request to get the next group of results. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The value that you specified for <code>MaxResults</code> in the request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value that you specified for <code>MaxResults</code> in the request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The value that you specified for <code>MaxResults</code> in the request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Appends an item to `resolver_rules`.
    ///
    /// To override the contents of this collection use [`set_resolver_rules`](Self::set_resolver_rules).
    ///
    /// <p>The Resolver rules that were created using the current Amazon Web Services account and that match the specified filters, if any.</p>
    pub fn resolver_rules(mut self, input: crate::types::ResolverRule) -> Self {
        let mut v = self.resolver_rules.unwrap_or_default();
        v.push(input);
        self.resolver_rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Resolver rules that were created using the current Amazon Web Services account and that match the specified filters, if any.</p>
    pub fn set_resolver_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResolverRule>>) -> Self {
        self.resolver_rules = input;
        self
    }
    /// <p>The Resolver rules that were created using the current Amazon Web Services account and that match the specified filters, if any.</p>
    pub fn get_resolver_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResolverRule>> {
        &self.resolver_rules
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListResolverRulesOutput`](crate::operation::list_resolver_rules::ListResolverRulesOutput).
    pub fn build(self) -> crate::operation::list_resolver_rules::ListResolverRulesOutput {
        crate::operation::list_resolver_rules::ListResolverRulesOutput {
            next_token: self.next_token,
            max_results: self.max_results,
            resolver_rules: self.resolver_rules,
            _request_id: self._request_id,
        }
    }
}
