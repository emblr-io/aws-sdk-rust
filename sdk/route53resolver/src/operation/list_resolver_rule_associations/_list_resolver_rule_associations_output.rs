// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResolverRuleAssociationsOutput {
    /// <p>If more than <code>MaxResults</code> rule associations match the specified criteria, you can submit another <code>ListResolverRuleAssociation</code> request to get the next group of results. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The value that you specified for <code>MaxResults</code> in the request.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The associations that were created between Resolver rules and VPCs using the current Amazon Web Services account, and that match the specified filters, if any.</p>
    pub resolver_rule_associations: ::std::option::Option<::std::vec::Vec<crate::types::ResolverRuleAssociation>>,
    _request_id: Option<String>,
}
impl ListResolverRuleAssociationsOutput {
    /// <p>If more than <code>MaxResults</code> rule associations match the specified criteria, you can submit another <code>ListResolverRuleAssociation</code> request to get the next group of results. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The value that you specified for <code>MaxResults</code> in the request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The associations that were created between Resolver rules and VPCs using the current Amazon Web Services account, and that match the specified filters, if any.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resolver_rule_associations.is_none()`.
    pub fn resolver_rule_associations(&self) -> &[crate::types::ResolverRuleAssociation] {
        self.resolver_rule_associations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListResolverRuleAssociationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListResolverRuleAssociationsOutput {
    /// Creates a new builder-style object to manufacture [`ListResolverRuleAssociationsOutput`](crate::operation::list_resolver_rule_associations::ListResolverRuleAssociationsOutput).
    pub fn builder() -> crate::operation::list_resolver_rule_associations::builders::ListResolverRuleAssociationsOutputBuilder {
        crate::operation::list_resolver_rule_associations::builders::ListResolverRuleAssociationsOutputBuilder::default()
    }
}

/// A builder for [`ListResolverRuleAssociationsOutput`](crate::operation::list_resolver_rule_associations::ListResolverRuleAssociationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResolverRuleAssociationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) resolver_rule_associations: ::std::option::Option<::std::vec::Vec<crate::types::ResolverRuleAssociation>>,
    _request_id: Option<String>,
}
impl ListResolverRuleAssociationsOutputBuilder {
    /// <p>If more than <code>MaxResults</code> rule associations match the specified criteria, you can submit another <code>ListResolverRuleAssociation</code> request to get the next group of results. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If more than <code>MaxResults</code> rule associations match the specified criteria, you can submit another <code>ListResolverRuleAssociation</code> request to get the next group of results. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If more than <code>MaxResults</code> rule associations match the specified criteria, you can submit another <code>ListResolverRuleAssociation</code> request to get the next group of results. In the next request, specify the value of <code>NextToken</code> from the previous response.</p>
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
    /// Appends an item to `resolver_rule_associations`.
    ///
    /// To override the contents of this collection use [`set_resolver_rule_associations`](Self::set_resolver_rule_associations).
    ///
    /// <p>The associations that were created between Resolver rules and VPCs using the current Amazon Web Services account, and that match the specified filters, if any.</p>
    pub fn resolver_rule_associations(mut self, input: crate::types::ResolverRuleAssociation) -> Self {
        let mut v = self.resolver_rule_associations.unwrap_or_default();
        v.push(input);
        self.resolver_rule_associations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The associations that were created between Resolver rules and VPCs using the current Amazon Web Services account, and that match the specified filters, if any.</p>
    pub fn set_resolver_rule_associations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResolverRuleAssociation>>) -> Self {
        self.resolver_rule_associations = input;
        self
    }
    /// <p>The associations that were created between Resolver rules and VPCs using the current Amazon Web Services account, and that match the specified filters, if any.</p>
    pub fn get_resolver_rule_associations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResolverRuleAssociation>> {
        &self.resolver_rule_associations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListResolverRuleAssociationsOutput`](crate::operation::list_resolver_rule_associations::ListResolverRuleAssociationsOutput).
    pub fn build(self) -> crate::operation::list_resolver_rule_associations::ListResolverRuleAssociationsOutput {
        crate::operation::list_resolver_rule_associations::ListResolverRuleAssociationsOutput {
            next_token: self.next_token,
            max_results: self.max_results,
            resolver_rule_associations: self.resolver_rule_associations,
            _request_id: self._request_id,
        }
    }
}
