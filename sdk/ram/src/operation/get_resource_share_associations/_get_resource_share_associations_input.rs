// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourceShareAssociationsInput {
    /// <p>Specifies whether you want to retrieve the associations that involve a specified resource or principal.</p>
    /// <ul>
    /// <li>
    /// <p><code>PRINCIPAL</code> – list the principals whose associations you want to see.</p></li>
    /// <li>
    /// <p><code>RESOURCE</code> – list the resources whose associations you want to see.</p></li>
    /// </ul>
    pub association_type: ::std::option::Option<crate::types::ResourceShareAssociationType>,
    /// <p>Specifies a list of <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> of the resource share whose associations you want to retrieve.</p>
    pub resource_share_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of a resource whose resource shares you want to retrieve.</p>
    /// <p>You cannot specify this parameter if the association type is <code>PRINCIPAL</code>.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the ID of the principal whose resource shares you want to retrieve. This can be an Amazon Web Services account ID, an organization ID, an organizational unit ID, or the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of an individual IAM role or user.</p>
    /// <p>You cannot specify this parameter if the association type is <code>RESOURCE</code>.</p>
    pub principal: ::std::option::Option<::std::string::String>,
    /// <p>Specifies that you want to retrieve only associations that have this status.</p>
    pub association_status: ::std::option::Option<crate::types::ResourceShareAssociationStatus>,
    /// <p>Specifies that you want to receive the next page of results. Valid only if you received a <code>NextToken</code> response in the previous request. If you did, it indicates that more output is available. Set this parameter to the value provided by the previous call's <code>NextToken</code> response to request the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the total number of results that you want included on each page of the response. If you do not include this parameter, it defaults to a value that is specific to the operation. If additional items exist beyond the number you specify, the <code>NextToken</code> response element is returned with a value (not null). Include the specified value as the <code>NextToken</code> request parameter in the next call to the operation to get the next part of the results. Note that the service might return fewer results than the maximum even when there are more results available. You should check <code>NextToken</code> after every operation to ensure that you receive all of the results.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl GetResourceShareAssociationsInput {
    /// <p>Specifies whether you want to retrieve the associations that involve a specified resource or principal.</p>
    /// <ul>
    /// <li>
    /// <p><code>PRINCIPAL</code> – list the principals whose associations you want to see.</p></li>
    /// <li>
    /// <p><code>RESOURCE</code> – list the resources whose associations you want to see.</p></li>
    /// </ul>
    pub fn association_type(&self) -> ::std::option::Option<&crate::types::ResourceShareAssociationType> {
        self.association_type.as_ref()
    }
    /// <p>Specifies a list of <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> of the resource share whose associations you want to retrieve.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_share_arns.is_none()`.
    pub fn resource_share_arns(&self) -> &[::std::string::String] {
        self.resource_share_arns.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of a resource whose resource shares you want to retrieve.</p>
    /// <p>You cannot specify this parameter if the association type is <code>PRINCIPAL</code>.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>Specifies the ID of the principal whose resource shares you want to retrieve. This can be an Amazon Web Services account ID, an organization ID, an organizational unit ID, or the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of an individual IAM role or user.</p>
    /// <p>You cannot specify this parameter if the association type is <code>RESOURCE</code>.</p>
    pub fn principal(&self) -> ::std::option::Option<&str> {
        self.principal.as_deref()
    }
    /// <p>Specifies that you want to retrieve only associations that have this status.</p>
    pub fn association_status(&self) -> ::std::option::Option<&crate::types::ResourceShareAssociationStatus> {
        self.association_status.as_ref()
    }
    /// <p>Specifies that you want to receive the next page of results. Valid only if you received a <code>NextToken</code> response in the previous request. If you did, it indicates that more output is available. Set this parameter to the value provided by the previous call's <code>NextToken</code> response to request the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Specifies the total number of results that you want included on each page of the response. If you do not include this parameter, it defaults to a value that is specific to the operation. If additional items exist beyond the number you specify, the <code>NextToken</code> response element is returned with a value (not null). Include the specified value as the <code>NextToken</code> request parameter in the next call to the operation to get the next part of the results. Note that the service might return fewer results than the maximum even when there are more results available. You should check <code>NextToken</code> after every operation to ensure that you receive all of the results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl GetResourceShareAssociationsInput {
    /// Creates a new builder-style object to manufacture [`GetResourceShareAssociationsInput`](crate::operation::get_resource_share_associations::GetResourceShareAssociationsInput).
    pub fn builder() -> crate::operation::get_resource_share_associations::builders::GetResourceShareAssociationsInputBuilder {
        crate::operation::get_resource_share_associations::builders::GetResourceShareAssociationsInputBuilder::default()
    }
}

/// A builder for [`GetResourceShareAssociationsInput`](crate::operation::get_resource_share_associations::GetResourceShareAssociationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourceShareAssociationsInputBuilder {
    pub(crate) association_type: ::std::option::Option<crate::types::ResourceShareAssociationType>,
    pub(crate) resource_share_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) principal: ::std::option::Option<::std::string::String>,
    pub(crate) association_status: ::std::option::Option<crate::types::ResourceShareAssociationStatus>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl GetResourceShareAssociationsInputBuilder {
    /// <p>Specifies whether you want to retrieve the associations that involve a specified resource or principal.</p>
    /// <ul>
    /// <li>
    /// <p><code>PRINCIPAL</code> – list the principals whose associations you want to see.</p></li>
    /// <li>
    /// <p><code>RESOURCE</code> – list the resources whose associations you want to see.</p></li>
    /// </ul>
    /// This field is required.
    pub fn association_type(mut self, input: crate::types::ResourceShareAssociationType) -> Self {
        self.association_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether you want to retrieve the associations that involve a specified resource or principal.</p>
    /// <ul>
    /// <li>
    /// <p><code>PRINCIPAL</code> – list the principals whose associations you want to see.</p></li>
    /// <li>
    /// <p><code>RESOURCE</code> – list the resources whose associations you want to see.</p></li>
    /// </ul>
    pub fn set_association_type(mut self, input: ::std::option::Option<crate::types::ResourceShareAssociationType>) -> Self {
        self.association_type = input;
        self
    }
    /// <p>Specifies whether you want to retrieve the associations that involve a specified resource or principal.</p>
    /// <ul>
    /// <li>
    /// <p><code>PRINCIPAL</code> – list the principals whose associations you want to see.</p></li>
    /// <li>
    /// <p><code>RESOURCE</code> – list the resources whose associations you want to see.</p></li>
    /// </ul>
    pub fn get_association_type(&self) -> &::std::option::Option<crate::types::ResourceShareAssociationType> {
        &self.association_type
    }
    /// Appends an item to `resource_share_arns`.
    ///
    /// To override the contents of this collection use [`set_resource_share_arns`](Self::set_resource_share_arns).
    ///
    /// <p>Specifies a list of <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> of the resource share whose associations you want to retrieve.</p>
    pub fn resource_share_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.resource_share_arns.unwrap_or_default();
        v.push(input.into());
        self.resource_share_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies a list of <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> of the resource share whose associations you want to retrieve.</p>
    pub fn set_resource_share_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.resource_share_arns = input;
        self
    }
    /// <p>Specifies a list of <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> of the resource share whose associations you want to retrieve.</p>
    pub fn get_resource_share_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.resource_share_arns
    }
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of a resource whose resource shares you want to retrieve.</p>
    /// <p>You cannot specify this parameter if the association type is <code>PRINCIPAL</code>.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of a resource whose resource shares you want to retrieve.</p>
    /// <p>You cannot specify this parameter if the association type is <code>PRINCIPAL</code>.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>Specifies the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of a resource whose resource shares you want to retrieve.</p>
    /// <p>You cannot specify this parameter if the association type is <code>PRINCIPAL</code>.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>Specifies the ID of the principal whose resource shares you want to retrieve. This can be an Amazon Web Services account ID, an organization ID, an organizational unit ID, or the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of an individual IAM role or user.</p>
    /// <p>You cannot specify this parameter if the association type is <code>RESOURCE</code>.</p>
    pub fn principal(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ID of the principal whose resource shares you want to retrieve. This can be an Amazon Web Services account ID, an organization ID, an organizational unit ID, or the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of an individual IAM role or user.</p>
    /// <p>You cannot specify this parameter if the association type is <code>RESOURCE</code>.</p>
    pub fn set_principal(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal = input;
        self
    }
    /// <p>Specifies the ID of the principal whose resource shares you want to retrieve. This can be an Amazon Web Services account ID, an organization ID, an organizational unit ID, or the <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Name (ARN)</a> of an individual IAM role or user.</p>
    /// <p>You cannot specify this parameter if the association type is <code>RESOURCE</code>.</p>
    pub fn get_principal(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal
    }
    /// <p>Specifies that you want to retrieve only associations that have this status.</p>
    pub fn association_status(mut self, input: crate::types::ResourceShareAssociationStatus) -> Self {
        self.association_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies that you want to retrieve only associations that have this status.</p>
    pub fn set_association_status(mut self, input: ::std::option::Option<crate::types::ResourceShareAssociationStatus>) -> Self {
        self.association_status = input;
        self
    }
    /// <p>Specifies that you want to retrieve only associations that have this status.</p>
    pub fn get_association_status(&self) -> &::std::option::Option<crate::types::ResourceShareAssociationStatus> {
        &self.association_status
    }
    /// <p>Specifies that you want to receive the next page of results. Valid only if you received a <code>NextToken</code> response in the previous request. If you did, it indicates that more output is available. Set this parameter to the value provided by the previous call's <code>NextToken</code> response to request the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies that you want to receive the next page of results. Valid only if you received a <code>NextToken</code> response in the previous request. If you did, it indicates that more output is available. Set this parameter to the value provided by the previous call's <code>NextToken</code> response to request the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Specifies that you want to receive the next page of results. Valid only if you received a <code>NextToken</code> response in the previous request. If you did, it indicates that more output is available. Set this parameter to the value provided by the previous call's <code>NextToken</code> response to request the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Specifies the total number of results that you want included on each page of the response. If you do not include this parameter, it defaults to a value that is specific to the operation. If additional items exist beyond the number you specify, the <code>NextToken</code> response element is returned with a value (not null). Include the specified value as the <code>NextToken</code> request parameter in the next call to the operation to get the next part of the results. Note that the service might return fewer results than the maximum even when there are more results available. You should check <code>NextToken</code> after every operation to ensure that you receive all of the results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the total number of results that you want included on each page of the response. If you do not include this parameter, it defaults to a value that is specific to the operation. If additional items exist beyond the number you specify, the <code>NextToken</code> response element is returned with a value (not null). Include the specified value as the <code>NextToken</code> request parameter in the next call to the operation to get the next part of the results. Note that the service might return fewer results than the maximum even when there are more results available. You should check <code>NextToken</code> after every operation to ensure that you receive all of the results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Specifies the total number of results that you want included on each page of the response. If you do not include this parameter, it defaults to a value that is specific to the operation. If additional items exist beyond the number you specify, the <code>NextToken</code> response element is returned with a value (not null). Include the specified value as the <code>NextToken</code> request parameter in the next call to the operation to get the next part of the results. Note that the service might return fewer results than the maximum even when there are more results available. You should check <code>NextToken</code> after every operation to ensure that you receive all of the results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`GetResourceShareAssociationsInput`](crate::operation::get_resource_share_associations::GetResourceShareAssociationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_resource_share_associations::GetResourceShareAssociationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_resource_share_associations::GetResourceShareAssociationsInput {
            association_type: self.association_type,
            resource_share_arns: self.resource_share_arns,
            resource_arn: self.resource_arn,
            principal: self.principal,
            association_status: self.association_status,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
