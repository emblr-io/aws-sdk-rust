// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteServiceLinkedRoleOutput {
    /// <p>The deletion task identifier that you can use to check the status of the deletion. This identifier is returned in the format <code>task/aws-service-role/<service-principal-name>
    /// /
    /// <role-name>
    /// /
    /// <task-uuid></task-uuid>
    /// </role-name>
    /// </service-principal-name></code>.</p>
    pub deletion_task_id: ::std::string::String,
    _request_id: Option<String>,
}
impl DeleteServiceLinkedRoleOutput {
    /// <p>The deletion task identifier that you can use to check the status of the deletion. This identifier is returned in the format <code>task/aws-service-role/<service-principal-name>
    /// /
    /// <role-name>
    /// /
    /// <task-uuid></task-uuid>
    /// </role-name>
    /// </service-principal-name></code>.</p>
    pub fn deletion_task_id(&self) -> &str {
        use std::ops::Deref;
        self.deletion_task_id.deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteServiceLinkedRoleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteServiceLinkedRoleOutput {
    /// Creates a new builder-style object to manufacture [`DeleteServiceLinkedRoleOutput`](crate::operation::delete_service_linked_role::DeleteServiceLinkedRoleOutput).
    pub fn builder() -> crate::operation::delete_service_linked_role::builders::DeleteServiceLinkedRoleOutputBuilder {
        crate::operation::delete_service_linked_role::builders::DeleteServiceLinkedRoleOutputBuilder::default()
    }
}

/// A builder for [`DeleteServiceLinkedRoleOutput`](crate::operation::delete_service_linked_role::DeleteServiceLinkedRoleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteServiceLinkedRoleOutputBuilder {
    pub(crate) deletion_task_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteServiceLinkedRoleOutputBuilder {
    /// <p>The deletion task identifier that you can use to check the status of the deletion. This identifier is returned in the format <code>task/aws-service-role/<service-principal-name>
    /// /
    /// <role-name>
    /// /
    /// <task-uuid></task-uuid>
    /// </role-name>
    /// </service-principal-name></code>.</p>
    /// This field is required.
    pub fn deletion_task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deletion_task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The deletion task identifier that you can use to check the status of the deletion. This identifier is returned in the format <code>task/aws-service-role/<service-principal-name>
    /// /
    /// <role-name>
    /// /
    /// <task-uuid></task-uuid>
    /// </role-name>
    /// </service-principal-name></code>.</p>
    pub fn set_deletion_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deletion_task_id = input;
        self
    }
    /// <p>The deletion task identifier that you can use to check the status of the deletion. This identifier is returned in the format <code>task/aws-service-role/<service-principal-name>
    /// /
    /// <role-name>
    /// /
    /// <task-uuid></task-uuid>
    /// </role-name>
    /// </service-principal-name></code>.</p>
    pub fn get_deletion_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.deletion_task_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteServiceLinkedRoleOutput`](crate::operation::delete_service_linked_role::DeleteServiceLinkedRoleOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`deletion_task_id`](crate::operation::delete_service_linked_role::builders::DeleteServiceLinkedRoleOutputBuilder::deletion_task_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_service_linked_role::DeleteServiceLinkedRoleOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_service_linked_role::DeleteServiceLinkedRoleOutput {
            deletion_task_id: self.deletion_task_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "deletion_task_id",
                    "deletion_task_id was not specified but it is required when building DeleteServiceLinkedRoleOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
