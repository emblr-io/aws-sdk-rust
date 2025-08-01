// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRepositoryLinksOutput {
    /// <p>Lists the repository links called by the list repository links operation.</p>
    pub repository_links: ::std::vec::Vec<crate::types::RepositoryLinkInfo>,
    /// <p>An enumeration token that allows the operation to batch the results of the operation.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRepositoryLinksOutput {
    /// <p>Lists the repository links called by the list repository links operation.</p>
    pub fn repository_links(&self) -> &[crate::types::RepositoryLinkInfo] {
        use std::ops::Deref;
        self.repository_links.deref()
    }
    /// <p>An enumeration token that allows the operation to batch the results of the operation.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListRepositoryLinksOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListRepositoryLinksOutput {
    /// Creates a new builder-style object to manufacture [`ListRepositoryLinksOutput`](crate::operation::list_repository_links::ListRepositoryLinksOutput).
    pub fn builder() -> crate::operation::list_repository_links::builders::ListRepositoryLinksOutputBuilder {
        crate::operation::list_repository_links::builders::ListRepositoryLinksOutputBuilder::default()
    }
}

/// A builder for [`ListRepositoryLinksOutput`](crate::operation::list_repository_links::ListRepositoryLinksOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRepositoryLinksOutputBuilder {
    pub(crate) repository_links: ::std::option::Option<::std::vec::Vec<crate::types::RepositoryLinkInfo>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRepositoryLinksOutputBuilder {
    /// Appends an item to `repository_links`.
    ///
    /// To override the contents of this collection use [`set_repository_links`](Self::set_repository_links).
    ///
    /// <p>Lists the repository links called by the list repository links operation.</p>
    pub fn repository_links(mut self, input: crate::types::RepositoryLinkInfo) -> Self {
        let mut v = self.repository_links.unwrap_or_default();
        v.push(input);
        self.repository_links = ::std::option::Option::Some(v);
        self
    }
    /// <p>Lists the repository links called by the list repository links operation.</p>
    pub fn set_repository_links(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RepositoryLinkInfo>>) -> Self {
        self.repository_links = input;
        self
    }
    /// <p>Lists the repository links called by the list repository links operation.</p>
    pub fn get_repository_links(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RepositoryLinkInfo>> {
        &self.repository_links
    }
    /// <p>An enumeration token that allows the operation to batch the results of the operation.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An enumeration token that allows the operation to batch the results of the operation.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An enumeration token that allows the operation to batch the results of the operation.</p>
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
    /// Consumes the builder and constructs a [`ListRepositoryLinksOutput`](crate::operation::list_repository_links::ListRepositoryLinksOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`repository_links`](crate::operation::list_repository_links::builders::ListRepositoryLinksOutputBuilder::repository_links)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_repository_links::ListRepositoryLinksOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_repository_links::ListRepositoryLinksOutput {
            repository_links: self.repository_links.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "repository_links",
                    "repository_links was not specified but it is required when building ListRepositoryLinksOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
