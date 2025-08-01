// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRepositoryOutput {
    /// <p>The repository link's detail data that's returned by Proton.</p>
    pub repository: ::std::option::Option<crate::types::Repository>,
    _request_id: Option<String>,
}
impl CreateRepositoryOutput {
    /// <p>The repository link's detail data that's returned by Proton.</p>
    pub fn repository(&self) -> ::std::option::Option<&crate::types::Repository> {
        self.repository.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateRepositoryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateRepositoryOutput {
    /// Creates a new builder-style object to manufacture [`CreateRepositoryOutput`](crate::operation::create_repository::CreateRepositoryOutput).
    pub fn builder() -> crate::operation::create_repository::builders::CreateRepositoryOutputBuilder {
        crate::operation::create_repository::builders::CreateRepositoryOutputBuilder::default()
    }
}

/// A builder for [`CreateRepositoryOutput`](crate::operation::create_repository::CreateRepositoryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRepositoryOutputBuilder {
    pub(crate) repository: ::std::option::Option<crate::types::Repository>,
    _request_id: Option<String>,
}
impl CreateRepositoryOutputBuilder {
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
    /// Consumes the builder and constructs a [`CreateRepositoryOutput`](crate::operation::create_repository::CreateRepositoryOutput).
    pub fn build(self) -> crate::operation::create_repository::CreateRepositoryOutput {
        crate::operation::create_repository::CreateRepositoryOutput {
            repository: self.repository,
            _request_id: self._request_id,
        }
    }
}
