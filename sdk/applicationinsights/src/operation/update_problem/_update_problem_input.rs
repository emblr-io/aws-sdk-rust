// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateProblemInput {
    /// <p>The ID of the problem.</p>
    pub problem_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the problem. Arguments can be passed for only problems that show a status of <code>RECOVERING</code>.</p>
    pub update_status: ::std::option::Option<crate::types::UpdateStatus>,
    /// <p>The visibility of a problem. When you pass a value of <code>IGNORED</code>, the problem is removed from the default view, and all notifications for the problem are suspended. When <code>VISIBLE</code> is passed, the <code>IGNORED</code> action is reversed.</p>
    pub visibility: ::std::option::Option<crate::types::Visibility>,
}
impl UpdateProblemInput {
    /// <p>The ID of the problem.</p>
    pub fn problem_id(&self) -> ::std::option::Option<&str> {
        self.problem_id.as_deref()
    }
    /// <p>The status of the problem. Arguments can be passed for only problems that show a status of <code>RECOVERING</code>.</p>
    pub fn update_status(&self) -> ::std::option::Option<&crate::types::UpdateStatus> {
        self.update_status.as_ref()
    }
    /// <p>The visibility of a problem. When you pass a value of <code>IGNORED</code>, the problem is removed from the default view, and all notifications for the problem are suspended. When <code>VISIBLE</code> is passed, the <code>IGNORED</code> action is reversed.</p>
    pub fn visibility(&self) -> ::std::option::Option<&crate::types::Visibility> {
        self.visibility.as_ref()
    }
}
impl UpdateProblemInput {
    /// Creates a new builder-style object to manufacture [`UpdateProblemInput`](crate::operation::update_problem::UpdateProblemInput).
    pub fn builder() -> crate::operation::update_problem::builders::UpdateProblemInputBuilder {
        crate::operation::update_problem::builders::UpdateProblemInputBuilder::default()
    }
}

/// A builder for [`UpdateProblemInput`](crate::operation::update_problem::UpdateProblemInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateProblemInputBuilder {
    pub(crate) problem_id: ::std::option::Option<::std::string::String>,
    pub(crate) update_status: ::std::option::Option<crate::types::UpdateStatus>,
    pub(crate) visibility: ::std::option::Option<crate::types::Visibility>,
}
impl UpdateProblemInputBuilder {
    /// <p>The ID of the problem.</p>
    /// This field is required.
    pub fn problem_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.problem_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the problem.</p>
    pub fn set_problem_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.problem_id = input;
        self
    }
    /// <p>The ID of the problem.</p>
    pub fn get_problem_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.problem_id
    }
    /// <p>The status of the problem. Arguments can be passed for only problems that show a status of <code>RECOVERING</code>.</p>
    pub fn update_status(mut self, input: crate::types::UpdateStatus) -> Self {
        self.update_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the problem. Arguments can be passed for only problems that show a status of <code>RECOVERING</code>.</p>
    pub fn set_update_status(mut self, input: ::std::option::Option<crate::types::UpdateStatus>) -> Self {
        self.update_status = input;
        self
    }
    /// <p>The status of the problem. Arguments can be passed for only problems that show a status of <code>RECOVERING</code>.</p>
    pub fn get_update_status(&self) -> &::std::option::Option<crate::types::UpdateStatus> {
        &self.update_status
    }
    /// <p>The visibility of a problem. When you pass a value of <code>IGNORED</code>, the problem is removed from the default view, and all notifications for the problem are suspended. When <code>VISIBLE</code> is passed, the <code>IGNORED</code> action is reversed.</p>
    pub fn visibility(mut self, input: crate::types::Visibility) -> Self {
        self.visibility = ::std::option::Option::Some(input);
        self
    }
    /// <p>The visibility of a problem. When you pass a value of <code>IGNORED</code>, the problem is removed from the default view, and all notifications for the problem are suspended. When <code>VISIBLE</code> is passed, the <code>IGNORED</code> action is reversed.</p>
    pub fn set_visibility(mut self, input: ::std::option::Option<crate::types::Visibility>) -> Self {
        self.visibility = input;
        self
    }
    /// <p>The visibility of a problem. When you pass a value of <code>IGNORED</code>, the problem is removed from the default view, and all notifications for the problem are suspended. When <code>VISIBLE</code> is passed, the <code>IGNORED</code> action is reversed.</p>
    pub fn get_visibility(&self) -> &::std::option::Option<crate::types::Visibility> {
        &self.visibility
    }
    /// Consumes the builder and constructs a [`UpdateProblemInput`](crate::operation::update_problem::UpdateProblemInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_problem::UpdateProblemInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_problem::UpdateProblemInput {
            problem_id: self.problem_id,
            update_status: self.update_status,
            visibility: self.visibility,
        })
    }
}
