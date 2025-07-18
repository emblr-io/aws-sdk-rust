// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSourceRepositoryBranchOutput {
    /// <p>The Git reference name of the branch.</p>
    pub r#ref: ::std::option::Option<::std::string::String>,
    /// <p>The name of the newly created branch.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The time the branch was last updated, in coordinated universal time (UTC) timestamp format as specified in <a href="https://www.rfc-editor.org/rfc/rfc3339#section-5.6">RFC 3339</a>.</p>
    pub last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The commit ID of the tip of the newly created branch.</p>
    pub head_commit_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateSourceRepositoryBranchOutput {
    /// <p>The Git reference name of the branch.</p>
    pub fn r#ref(&self) -> ::std::option::Option<&str> {
        self.r#ref.as_deref()
    }
    /// <p>The name of the newly created branch.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The time the branch was last updated, in coordinated universal time (UTC) timestamp format as specified in <a href="https://www.rfc-editor.org/rfc/rfc3339#section-5.6">RFC 3339</a>.</p>
    pub fn last_updated_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_time.as_ref()
    }
    /// <p>The commit ID of the tip of the newly created branch.</p>
    pub fn head_commit_id(&self) -> ::std::option::Option<&str> {
        self.head_commit_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateSourceRepositoryBranchOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateSourceRepositoryBranchOutput {
    /// Creates a new builder-style object to manufacture [`CreateSourceRepositoryBranchOutput`](crate::operation::create_source_repository_branch::CreateSourceRepositoryBranchOutput).
    pub fn builder() -> crate::operation::create_source_repository_branch::builders::CreateSourceRepositoryBranchOutputBuilder {
        crate::operation::create_source_repository_branch::builders::CreateSourceRepositoryBranchOutputBuilder::default()
    }
}

/// A builder for [`CreateSourceRepositoryBranchOutput`](crate::operation::create_source_repository_branch::CreateSourceRepositoryBranchOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSourceRepositoryBranchOutputBuilder {
    pub(crate) r#ref: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) head_commit_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateSourceRepositoryBranchOutputBuilder {
    /// <p>The Git reference name of the branch.</p>
    pub fn r#ref(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#ref = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Git reference name of the branch.</p>
    pub fn set_ref(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#ref = input;
        self
    }
    /// <p>The Git reference name of the branch.</p>
    pub fn get_ref(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#ref
    }
    /// <p>The name of the newly created branch.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the newly created branch.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the newly created branch.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The time the branch was last updated, in coordinated universal time (UTC) timestamp format as specified in <a href="https://www.rfc-editor.org/rfc/rfc3339#section-5.6">RFC 3339</a>.</p>
    pub fn last_updated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the branch was last updated, in coordinated universal time (UTC) timestamp format as specified in <a href="https://www.rfc-editor.org/rfc/rfc3339#section-5.6">RFC 3339</a>.</p>
    pub fn set_last_updated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_time = input;
        self
    }
    /// <p>The time the branch was last updated, in coordinated universal time (UTC) timestamp format as specified in <a href="https://www.rfc-editor.org/rfc/rfc3339#section-5.6">RFC 3339</a>.</p>
    pub fn get_last_updated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_time
    }
    /// <p>The commit ID of the tip of the newly created branch.</p>
    pub fn head_commit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.head_commit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The commit ID of the tip of the newly created branch.</p>
    pub fn set_head_commit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.head_commit_id = input;
        self
    }
    /// <p>The commit ID of the tip of the newly created branch.</p>
    pub fn get_head_commit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.head_commit_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateSourceRepositoryBranchOutput`](crate::operation::create_source_repository_branch::CreateSourceRepositoryBranchOutput).
    pub fn build(self) -> crate::operation::create_source_repository_branch::CreateSourceRepositoryBranchOutput {
        crate::operation::create_source_repository_branch::CreateSourceRepositoryBranchOutput {
            r#ref: self.r#ref,
            name: self.name,
            last_updated_time: self.last_updated_time,
            head_commit_id: self.head_commit_id,
            _request_id: self._request_id,
        }
    }
}
