// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the trust relationships for a particular Managed Microsoft AD directory. If no input parameters are provided, such as directory ID or trust ID, this request describes all the trust relationships.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTrustsInput {
    /// <p>The Directory ID of the Amazon Web Services directory that is a part of the requested trust relationship.</p>
    pub directory_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of identifiers of the trust relationships for which to obtain the information. If this member is null, all trust relationships that belong to the current account are returned.</p>
    /// <p>An empty list results in an <code>InvalidParameterException</code> being thrown.</p>
    pub trust_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The <i>DescribeTrustsResult.NextToken</i> value from a previous call to <code>DescribeTrusts</code>. Pass null if this is the first call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of objects to return.</p>
    pub limit: ::std::option::Option<i32>,
}
impl DescribeTrustsInput {
    /// <p>The Directory ID of the Amazon Web Services directory that is a part of the requested trust relationship.</p>
    pub fn directory_id(&self) -> ::std::option::Option<&str> {
        self.directory_id.as_deref()
    }
    /// <p>A list of identifiers of the trust relationships for which to obtain the information. If this member is null, all trust relationships that belong to the current account are returned.</p>
    /// <p>An empty list results in an <code>InvalidParameterException</code> being thrown.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.trust_ids.is_none()`.
    pub fn trust_ids(&self) -> &[::std::string::String] {
        self.trust_ids.as_deref().unwrap_or_default()
    }
    /// <p>The <i>DescribeTrustsResult.NextToken</i> value from a previous call to <code>DescribeTrusts</code>. Pass null if this is the first call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of objects to return.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
}
impl DescribeTrustsInput {
    /// Creates a new builder-style object to manufacture [`DescribeTrustsInput`](crate::operation::describe_trusts::DescribeTrustsInput).
    pub fn builder() -> crate::operation::describe_trusts::builders::DescribeTrustsInputBuilder {
        crate::operation::describe_trusts::builders::DescribeTrustsInputBuilder::default()
    }
}

/// A builder for [`DescribeTrustsInput`](crate::operation::describe_trusts::DescribeTrustsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTrustsInputBuilder {
    pub(crate) directory_id: ::std::option::Option<::std::string::String>,
    pub(crate) trust_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
}
impl DescribeTrustsInputBuilder {
    /// <p>The Directory ID of the Amazon Web Services directory that is a part of the requested trust relationship.</p>
    pub fn directory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Directory ID of the Amazon Web Services directory that is a part of the requested trust relationship.</p>
    pub fn set_directory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_id = input;
        self
    }
    /// <p>The Directory ID of the Amazon Web Services directory that is a part of the requested trust relationship.</p>
    pub fn get_directory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_id
    }
    /// Appends an item to `trust_ids`.
    ///
    /// To override the contents of this collection use [`set_trust_ids`](Self::set_trust_ids).
    ///
    /// <p>A list of identifiers of the trust relationships for which to obtain the information. If this member is null, all trust relationships that belong to the current account are returned.</p>
    /// <p>An empty list results in an <code>InvalidParameterException</code> being thrown.</p>
    pub fn trust_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.trust_ids.unwrap_or_default();
        v.push(input.into());
        self.trust_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of identifiers of the trust relationships for which to obtain the information. If this member is null, all trust relationships that belong to the current account are returned.</p>
    /// <p>An empty list results in an <code>InvalidParameterException</code> being thrown.</p>
    pub fn set_trust_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.trust_ids = input;
        self
    }
    /// <p>A list of identifiers of the trust relationships for which to obtain the information. If this member is null, all trust relationships that belong to the current account are returned.</p>
    /// <p>An empty list results in an <code>InvalidParameterException</code> being thrown.</p>
    pub fn get_trust_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.trust_ids
    }
    /// <p>The <i>DescribeTrustsResult.NextToken</i> value from a previous call to <code>DescribeTrusts</code>. Pass null if this is the first call.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <i>DescribeTrustsResult.NextToken</i> value from a previous call to <code>DescribeTrusts</code>. Pass null if this is the first call.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <i>DescribeTrustsResult.NextToken</i> value from a previous call to <code>DescribeTrusts</code>. Pass null if this is the first call.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of objects to return.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of objects to return.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of objects to return.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// Consumes the builder and constructs a [`DescribeTrustsInput`](crate::operation::describe_trusts::DescribeTrustsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_trusts::DescribeTrustsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_trusts::DescribeTrustsInput {
            directory_id: self.directory_id,
            trust_ids: self.trust_ids,
            next_token: self.next_token,
            limit: self.limit,
        })
    }
}
