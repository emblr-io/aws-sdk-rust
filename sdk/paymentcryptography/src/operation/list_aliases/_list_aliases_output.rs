// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAliasesOutput {
    /// <p>The list of aliases. Each alias describes the <code>KeyArn</code> contained within.</p>
    pub aliases: ::std::vec::Vec<crate::types::Alias>,
    /// <p>The token for the next set of results, or an empty or null value if there are no more results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAliasesOutput {
    /// <p>The list of aliases. Each alias describes the <code>KeyArn</code> contained within.</p>
    pub fn aliases(&self) -> &[crate::types::Alias] {
        use std::ops::Deref;
        self.aliases.deref()
    }
    /// <p>The token for the next set of results, or an empty or null value if there are no more results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListAliasesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListAliasesOutput {
    /// Creates a new builder-style object to manufacture [`ListAliasesOutput`](crate::operation::list_aliases::ListAliasesOutput).
    pub fn builder() -> crate::operation::list_aliases::builders::ListAliasesOutputBuilder {
        crate::operation::list_aliases::builders::ListAliasesOutputBuilder::default()
    }
}

/// A builder for [`ListAliasesOutput`](crate::operation::list_aliases::ListAliasesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAliasesOutputBuilder {
    pub(crate) aliases: ::std::option::Option<::std::vec::Vec<crate::types::Alias>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAliasesOutputBuilder {
    /// Appends an item to `aliases`.
    ///
    /// To override the contents of this collection use [`set_aliases`](Self::set_aliases).
    ///
    /// <p>The list of aliases. Each alias describes the <code>KeyArn</code> contained within.</p>
    pub fn aliases(mut self, input: crate::types::Alias) -> Self {
        let mut v = self.aliases.unwrap_or_default();
        v.push(input);
        self.aliases = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of aliases. Each alias describes the <code>KeyArn</code> contained within.</p>
    pub fn set_aliases(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Alias>>) -> Self {
        self.aliases = input;
        self
    }
    /// <p>The list of aliases. Each alias describes the <code>KeyArn</code> contained within.</p>
    pub fn get_aliases(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Alias>> {
        &self.aliases
    }
    /// <p>The token for the next set of results, or an empty or null value if there are no more results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or an empty or null value if there are no more results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or an empty or null value if there are no more results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListAliasesOutput`](crate::operation::list_aliases::ListAliasesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`aliases`](crate::operation::list_aliases::builders::ListAliasesOutputBuilder::aliases)
    pub fn build(self) -> ::std::result::Result<crate::operation::list_aliases::ListAliasesOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_aliases::ListAliasesOutput {
            aliases: self.aliases.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "aliases",
                    "aliases was not specified but it is required when building ListAliasesOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
