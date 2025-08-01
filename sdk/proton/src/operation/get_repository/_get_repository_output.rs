// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRepositoryOutput {
    /// <p>The repository link's detail data that's returned by Proton.</p>
    pub repository: ::std::option::Option<crate::types::Repository>,
    _request_id: Option<String>,
}
impl GetRepositoryOutput {
    /// <p>The repository link's detail data that's returned by Proton.</p>
    pub fn repository(&self) -> ::std::option::Option<&crate::types::Repository> {
        self.repository.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetRepositoryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRepositoryOutput {
    /// Creates a new builder-style object to manufacture [`GetRepositoryOutput`](crate::operation::get_repository::GetRepositoryOutput).
    pub fn builder() -> crate::operation::get_repository::builders::GetRepositoryOutputBuilder {
        crate::operation::get_repository::builders::GetRepositoryOutputBuilder::default()
    }
}

/// A builder for [`GetRepositoryOutput`](crate::operation::get_repository::GetRepositoryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRepositoryOutputBuilder {
    pub(crate) repository: ::std::option::Option<crate::types::Repository>,
    _request_id: Option<String>,
}
impl GetRepositoryOutputBuilder {
    /// <p>The repository link's detail data that's returned by Proton.</p>
    /// This field is required.
    pub fn repository(mut self, input: crate::types::Repository) -> Self {
        self.repository = ::std::option::Option::Some(input);
        self
    }
    /// <p>The repository link's detail data that's returned by Proton.</p>
    pub fn set_repository(mut self, input: ::std::option::Option<crate::types::Repository>) -> Self {
        self.repository = input;
        self
    }
    /// <p>The repository link's detail data that's returned by Proton.</p>
    pub fn get_repository(&self) -> &::std::option::Option<crate::types::Repository> {
        &self.repository
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRepositoryOutput`](crate::operation::get_repository::GetRepositoryOutput).
    pub fn build(self) -> crate::operation::get_repository::GetRepositoryOutput {
        crate::operation::get_repository::GetRepositoryOutput {
            repository: self.repository,
            _request_id: self._request_id,
        }
    }
}
