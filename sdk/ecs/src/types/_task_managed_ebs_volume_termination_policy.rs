// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The termination policy for the Amazon EBS volume when the task exits. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ebs-volumes.html#ebs-volume-types">Amazon ECS volume termination policy</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaskManagedEbsVolumeTerminationPolicy {
    /// <p>Indicates whether the volume should be deleted on when the task stops. If a value of <code>true</code> is specified,  Amazon ECS deletes the Amazon EBS volume on your behalf when the task goes into the <code>STOPPED</code> state. If no value is specified, the  default value is <code>true</code> is used. When set to <code>false</code>, Amazon ECS leaves the volume in your  account.</p>
    pub delete_on_termination: bool,
}
impl TaskManagedEbsVolumeTerminationPolicy {
    /// <p>Indicates whether the volume should be deleted on when the task stops. If a value of <code>true</code> is specified,  Amazon ECS deletes the Amazon EBS volume on your behalf when the task goes into the <code>STOPPED</code> state. If no value is specified, the  default value is <code>true</code> is used. When set to <code>false</code>, Amazon ECS leaves the volume in your  account.</p>
    pub fn delete_on_termination(&self) -> bool {
        self.delete_on_termination
    }
}
impl TaskManagedEbsVolumeTerminationPolicy {
    /// Creates a new builder-style object to manufacture [`TaskManagedEbsVolumeTerminationPolicy`](crate::types::TaskManagedEbsVolumeTerminationPolicy).
    pub fn builder() -> crate::types::builders::TaskManagedEbsVolumeTerminationPolicyBuilder {
        crate::types::builders::TaskManagedEbsVolumeTerminationPolicyBuilder::default()
    }
}

/// A builder for [`TaskManagedEbsVolumeTerminationPolicy`](crate::types::TaskManagedEbsVolumeTerminationPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaskManagedEbsVolumeTerminationPolicyBuilder {
    pub(crate) delete_on_termination: ::std::option::Option<bool>,
}
impl TaskManagedEbsVolumeTerminationPolicyBuilder {
    /// <p>Indicates whether the volume should be deleted on when the task stops. If a value of <code>true</code> is specified,  Amazon ECS deletes the Amazon EBS volume on your behalf when the task goes into the <code>STOPPED</code> state. If no value is specified, the  default value is <code>true</code> is used. When set to <code>false</code>, Amazon ECS leaves the volume in your  account.</p>
    /// This field is required.
    pub fn delete_on_termination(mut self, input: bool) -> Self {
        self.delete_on_termination = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the volume should be deleted on when the task stops. If a value of <code>true</code> is specified,  Amazon ECS deletes the Amazon EBS volume on your behalf when the task goes into the <code>STOPPED</code> state. If no value is specified, the  default value is <code>true</code> is used. When set to <code>false</code>, Amazon ECS leaves the volume in your  account.</p>
    pub fn set_delete_on_termination(mut self, input: ::std::option::Option<bool>) -> Self {
        self.delete_on_termination = input;
        self
    }
    /// <p>Indicates whether the volume should be deleted on when the task stops. If a value of <code>true</code> is specified,  Amazon ECS deletes the Amazon EBS volume on your behalf when the task goes into the <code>STOPPED</code> state. If no value is specified, the  default value is <code>true</code> is used. When set to <code>false</code>, Amazon ECS leaves the volume in your  account.</p>
    pub fn get_delete_on_termination(&self) -> &::std::option::Option<bool> {
        &self.delete_on_termination
    }
    /// Consumes the builder and constructs a [`TaskManagedEbsVolumeTerminationPolicy`](crate::types::TaskManagedEbsVolumeTerminationPolicy).
    /// This method will fail if any of the following fields are not set:
    /// - [`delete_on_termination`](crate::types::builders::TaskManagedEbsVolumeTerminationPolicyBuilder::delete_on_termination)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::TaskManagedEbsVolumeTerminationPolicy, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TaskManagedEbsVolumeTerminationPolicy {
            delete_on_termination: self.delete_on_termination.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "delete_on_termination",
                    "delete_on_termination was not specified but it is required when building TaskManagedEbsVolumeTerminationPolicy",
                )
            })?,
        })
    }
}
