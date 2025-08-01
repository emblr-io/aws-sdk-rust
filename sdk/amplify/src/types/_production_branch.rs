// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the information about a production branch for an Amplify app.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProductionBranch {
    /// <p>The last deploy time of the production branch.</p>
    pub last_deploy_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status of the production branch.</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The thumbnail URL for the production branch.</p>
    pub thumbnail_url: ::std::option::Option<::std::string::String>,
    /// <p>The branch name for the production branch.</p>
    pub branch_name: ::std::option::Option<::std::string::String>,
}
impl ProductionBranch {
    /// <p>The last deploy time of the production branch.</p>
    pub fn last_deploy_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_deploy_time.as_ref()
    }
    /// <p>The status of the production branch.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The thumbnail URL for the production branch.</p>
    pub fn thumbnail_url(&self) -> ::std::option::Option<&str> {
        self.thumbnail_url.as_deref()
    }
    /// <p>The branch name for the production branch.</p>
    pub fn branch_name(&self) -> ::std::option::Option<&str> {
        self.branch_name.as_deref()
    }
}
impl ProductionBranch {
    /// Creates a new builder-style object to manufacture [`ProductionBranch`](crate::types::ProductionBranch).
    pub fn builder() -> crate::types::builders::ProductionBranchBuilder {
        crate::types::builders::ProductionBranchBuilder::default()
    }
}

/// A builder for [`ProductionBranch`](crate::types::ProductionBranch).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProductionBranchBuilder {
    pub(crate) last_deploy_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) thumbnail_url: ::std::option::Option<::std::string::String>,
    pub(crate) branch_name: ::std::option::Option<::std::string::String>,
}
impl ProductionBranchBuilder {
    /// <p>The last deploy time of the production branch.</p>
    pub fn last_deploy_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_deploy_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last deploy time of the production branch.</p>
    pub fn set_last_deploy_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_deploy_time = input;
        self
    }
    /// <p>The last deploy time of the production branch.</p>
    pub fn get_last_deploy_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_deploy_time
    }
    /// <p>The status of the production branch.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the production branch.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the production branch.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The thumbnail URL for the production branch.</p>
    pub fn thumbnail_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thumbnail_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The thumbnail URL for the production branch.</p>
    pub fn set_thumbnail_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thumbnail_url = input;
        self
    }
    /// <p>The thumbnail URL for the production branch.</p>
    pub fn get_thumbnail_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.thumbnail_url
    }
    /// <p>The branch name for the production branch.</p>
    pub fn branch_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.branch_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The branch name for the production branch.</p>
    pub fn set_branch_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.branch_name = input;
        self
    }
    /// <p>The branch name for the production branch.</p>
    pub fn get_branch_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.branch_name
    }
    /// Consumes the builder and constructs a [`ProductionBranch`](crate::types::ProductionBranch).
    pub fn build(self) -> crate::types::ProductionBranch {
        crate::types::ProductionBranch {
            last_deploy_time: self.last_deploy_time,
            status: self.status,
            thumbnail_url: self.thumbnail_url,
            branch_name: self.branch_name,
        }
    }
}
