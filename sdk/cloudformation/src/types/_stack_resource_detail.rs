// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains detailed information about the specified stack resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StackResourceDetail {
    /// <p>The name associated with the stack.</p>
    pub stack_name: ::std::option::Option<::std::string::String>,
    /// <p>Unique identifier of the stack.</p>
    pub stack_id: ::std::option::Option<::std::string::String>,
    /// <p>The logical name of the resource specified in the template.</p>
    pub logical_resource_id: ::std::option::Option<::std::string::String>,
    /// <p>The name or unique identifier that corresponds to a physical instance ID of a resource supported by CloudFormation.</p>
    pub physical_resource_id: ::std::option::Option<::std::string::String>,
    /// <p>Type of resource. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html">Amazon Web Services resource and property types reference</a> in the <i>CloudFormation User Guide</i>.</p>
    pub resource_type: ::std::option::Option<::std::string::String>,
    /// <p>Time the status was updated.</p>
    pub last_updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Current status of the resource.</p>
    pub resource_status: ::std::option::Option<crate::types::ResourceStatus>,
    /// <p>Success/failure message associated with the resource.</p>
    pub resource_status_reason: ::std::option::Option<::std::string::String>,
    /// <p>User defined description associated with the resource.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The content of the <code>Metadata</code> attribute declared for the resource. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-metadata.html">Metadata attribute</a> in the <i>CloudFormation User Guide</i>.</p>
    pub metadata: ::std::option::Option<::std::string::String>,
    /// <p>Information about whether the resource's actual configuration differs, or has <i>drifted</i>, from its expected configuration, as defined in the stack template and any values specified as template parameters. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html">Detect unmanaged configuration changes to stacks and resources with drift detection</a>.</p>
    pub drift_information: ::std::option::Option<crate::types::StackResourceDriftInformation>,
    /// <p>Contains information about the module from which the resource was created, if the resource was created from a module included in the stack template.</p>
    pub module_info: ::std::option::Option<crate::types::ModuleInfo>,
}
impl StackResourceDetail {
    /// <p>The name associated with the stack.</p>
    pub fn stack_name(&self) -> ::std::option::Option<&str> {
        self.stack_name.as_deref()
    }
    /// <p>Unique identifier of the stack.</p>
    pub fn stack_id(&self) -> ::std::option::Option<&str> {
        self.stack_id.as_deref()
    }
    /// <p>The logical name of the resource specified in the template.</p>
    pub fn logical_resource_id(&self) -> ::std::option::Option<&str> {
        self.logical_resource_id.as_deref()
    }
    /// <p>The name or unique identifier that corresponds to a physical instance ID of a resource supported by CloudFormation.</p>
    pub fn physical_resource_id(&self) -> ::std::option::Option<&str> {
        self.physical_resource_id.as_deref()
    }
    /// <p>Type of resource. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html">Amazon Web Services resource and property types reference</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&str> {
        self.resource_type.as_deref()
    }
    /// <p>Time the status was updated.</p>
    pub fn last_updated_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_timestamp.as_ref()
    }
    /// <p>Current status of the resource.</p>
    pub fn resource_status(&self) -> ::std::option::Option<&crate::types::ResourceStatus> {
        self.resource_status.as_ref()
    }
    /// <p>Success/failure message associated with the resource.</p>
    pub fn resource_status_reason(&self) -> ::std::option::Option<&str> {
        self.resource_status_reason.as_deref()
    }
    /// <p>User defined description associated with the resource.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The content of the <code>Metadata</code> attribute declared for the resource. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-metadata.html">Metadata attribute</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn metadata(&self) -> ::std::option::Option<&str> {
        self.metadata.as_deref()
    }
    /// <p>Information about whether the resource's actual configuration differs, or has <i>drifted</i>, from its expected configuration, as defined in the stack template and any values specified as template parameters. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html">Detect unmanaged configuration changes to stacks and resources with drift detection</a>.</p>
    pub fn drift_information(&self) -> ::std::option::Option<&crate::types::StackResourceDriftInformation> {
        self.drift_information.as_ref()
    }
    /// <p>Contains information about the module from which the resource was created, if the resource was created from a module included in the stack template.</p>
    pub fn module_info(&self) -> ::std::option::Option<&crate::types::ModuleInfo> {
        self.module_info.as_ref()
    }
}
impl StackResourceDetail {
    /// Creates a new builder-style object to manufacture [`StackResourceDetail`](crate::types::StackResourceDetail).
    pub fn builder() -> crate::types::builders::StackResourceDetailBuilder {
        crate::types::builders::StackResourceDetailBuilder::default()
    }
}

/// A builder for [`StackResourceDetail`](crate::types::StackResourceDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StackResourceDetailBuilder {
    pub(crate) stack_name: ::std::option::Option<::std::string::String>,
    pub(crate) stack_id: ::std::option::Option<::std::string::String>,
    pub(crate) logical_resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) physical_resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) resource_status: ::std::option::Option<crate::types::ResourceStatus>,
    pub(crate) resource_status_reason: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) metadata: ::std::option::Option<::std::string::String>,
    pub(crate) drift_information: ::std::option::Option<crate::types::StackResourceDriftInformation>,
    pub(crate) module_info: ::std::option::Option<crate::types::ModuleInfo>,
}
impl StackResourceDetailBuilder {
    /// <p>The name associated with the stack.</p>
    pub fn stack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name associated with the stack.</p>
    pub fn set_stack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_name = input;
        self
    }
    /// <p>The name associated with the stack.</p>
    pub fn get_stack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_name
    }
    /// <p>Unique identifier of the stack.</p>
    pub fn stack_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier of the stack.</p>
    pub fn set_stack_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_id = input;
        self
    }
    /// <p>Unique identifier of the stack.</p>
    pub fn get_stack_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_id
    }
    /// <p>The logical name of the resource specified in the template.</p>
    /// This field is required.
    pub fn logical_resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.logical_resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The logical name of the resource specified in the template.</p>
    pub fn set_logical_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.logical_resource_id = input;
        self
    }
    /// <p>The logical name of the resource specified in the template.</p>
    pub fn get_logical_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.logical_resource_id
    }
    /// <p>The name or unique identifier that corresponds to a physical instance ID of a resource supported by CloudFormation.</p>
    pub fn physical_resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.physical_resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or unique identifier that corresponds to a physical instance ID of a resource supported by CloudFormation.</p>
    pub fn set_physical_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.physical_resource_id = input;
        self
    }
    /// <p>The name or unique identifier that corresponds to a physical instance ID of a resource supported by CloudFormation.</p>
    pub fn get_physical_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.physical_resource_id
    }
    /// <p>Type of resource. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html">Amazon Web Services resource and property types reference</a> in the <i>CloudFormation User Guide</i>.</p>
    /// This field is required.
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Type of resource. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html">Amazon Web Services resource and property types reference</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>Type of resource. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html">Amazon Web Services resource and property types reference</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// <p>Time the status was updated.</p>
    /// This field is required.
    pub fn last_updated_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>Time the status was updated.</p>
    pub fn set_last_updated_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_timestamp = input;
        self
    }
    /// <p>Time the status was updated.</p>
    pub fn get_last_updated_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_timestamp
    }
    /// <p>Current status of the resource.</p>
    /// This field is required.
    pub fn resource_status(mut self, input: crate::types::ResourceStatus) -> Self {
        self.resource_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Current status of the resource.</p>
    pub fn set_resource_status(mut self, input: ::std::option::Option<crate::types::ResourceStatus>) -> Self {
        self.resource_status = input;
        self
    }
    /// <p>Current status of the resource.</p>
    pub fn get_resource_status(&self) -> &::std::option::Option<crate::types::ResourceStatus> {
        &self.resource_status
    }
    /// <p>Success/failure message associated with the resource.</p>
    pub fn resource_status_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_status_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Success/failure message associated with the resource.</p>
    pub fn set_resource_status_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_status_reason = input;
        self
    }
    /// <p>Success/failure message associated with the resource.</p>
    pub fn get_resource_status_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_status_reason
    }
    /// <p>User defined description associated with the resource.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>User defined description associated with the resource.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>User defined description associated with the resource.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The content of the <code>Metadata</code> attribute declared for the resource. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-metadata.html">Metadata attribute</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn metadata(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metadata = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content of the <code>Metadata</code> attribute declared for the resource. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-metadata.html">Metadata attribute</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn set_metadata(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metadata = input;
        self
    }
    /// <p>The content of the <code>Metadata</code> attribute declared for the resource. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-metadata.html">Metadata attribute</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn get_metadata(&self) -> &::std::option::Option<::std::string::String> {
        &self.metadata
    }
    /// <p>Information about whether the resource's actual configuration differs, or has <i>drifted</i>, from its expected configuration, as defined in the stack template and any values specified as template parameters. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html">Detect unmanaged configuration changes to stacks and resources with drift detection</a>.</p>
    pub fn drift_information(mut self, input: crate::types::StackResourceDriftInformation) -> Self {
        self.drift_information = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about whether the resource's actual configuration differs, or has <i>drifted</i>, from its expected configuration, as defined in the stack template and any values specified as template parameters. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html">Detect unmanaged configuration changes to stacks and resources with drift detection</a>.</p>
    pub fn set_drift_information(mut self, input: ::std::option::Option<crate::types::StackResourceDriftInformation>) -> Self {
        self.drift_information = input;
        self
    }
    /// <p>Information about whether the resource's actual configuration differs, or has <i>drifted</i>, from its expected configuration, as defined in the stack template and any values specified as template parameters. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html">Detect unmanaged configuration changes to stacks and resources with drift detection</a>.</p>
    pub fn get_drift_information(&self) -> &::std::option::Option<crate::types::StackResourceDriftInformation> {
        &self.drift_information
    }
    /// <p>Contains information about the module from which the resource was created, if the resource was created from a module included in the stack template.</p>
    pub fn module_info(mut self, input: crate::types::ModuleInfo) -> Self {
        self.module_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the module from which the resource was created, if the resource was created from a module included in the stack template.</p>
    pub fn set_module_info(mut self, input: ::std::option::Option<crate::types::ModuleInfo>) -> Self {
        self.module_info = input;
        self
    }
    /// <p>Contains information about the module from which the resource was created, if the resource was created from a module included in the stack template.</p>
    pub fn get_module_info(&self) -> &::std::option::Option<crate::types::ModuleInfo> {
        &self.module_info
    }
    /// Consumes the builder and constructs a [`StackResourceDetail`](crate::types::StackResourceDetail).
    pub fn build(self) -> crate::types::StackResourceDetail {
        crate::types::StackResourceDetail {
            stack_name: self.stack_name,
            stack_id: self.stack_id,
            logical_resource_id: self.logical_resource_id,
            physical_resource_id: self.physical_resource_id,
            resource_type: self.resource_type,
            last_updated_timestamp: self.last_updated_timestamp,
            resource_status: self.resource_status,
            resource_status_reason: self.resource_status_reason,
            description: self.description,
            metadata: self.metadata,
            drift_information: self.drift_information,
            module_info: self.module_info,
        }
    }
}
