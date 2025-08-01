// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetControlOutput {
    /// <p>The Amazon Resource Name (ARN) of the control.</p>
    pub arn: ::std::string::String,
    /// <p>A list of alternative identifiers for the control. These are human-readable designators, such as <code>SH.S3.1</code>. Several aliases can refer to the same control across different Amazon Web Services services or compliance frameworks.</p>
    pub aliases: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The display name of the control.</p>
    pub name: ::std::string::String,
    /// <p>A description of what the control does.</p>
    pub description: ::std::string::String,
    /// <p>A term that identifies the control's functional behavior. One of <code>Preventive</code>, <code>Detective</code>, <code>Proactive</code></p>
    pub behavior: crate::types::ControlBehavior,
    /// <p>An enumerated type, with the following possible values:</p>
    pub severity: ::std::option::Option<crate::types::ControlSeverity>,
    /// <p>Returns information about the control, including the scope of the control, if enabled, and the Regions in which the control is available for deployment. For more information about scope, see <a href="https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/global-services.html">Global services</a>.</p>
    /// <p>If you are applying controls through an Amazon Web Services Control Tower landing zone environment, remember that the values returned in the <code>RegionConfiguration</code> API operation are not related to the governed Regions in your landing zone. For example, if you are governing Regions <code>A</code>,<code>B</code>,and <code>C</code> while the control is available in Regions <code>A</code>, <code>B</code>, C<code>,</code> and <code>D</code>, you'd see a response with <code>DeployableRegions</code> of <code>A</code>, <code>B</code>, <code>C</code>, and <code>D</code> for a control with <code>REGIONAL</code> scope, even though you may not intend to deploy the control in Region <code>D</code>, because you do not govern it through your landing zone.</p>
    pub region_configuration: ::std::option::Option<crate::types::RegionConfiguration>,
    /// <p>Returns information about the control, as an <code>ImplementationDetails</code> object that shows the underlying implementation type for a control.</p>
    pub implementation: ::std::option::Option<crate::types::ImplementationDetails>,
    /// <p>Returns an array of <code>ControlParameter</code> objects that specify the parameters a control supports. An empty list is returned for controls that don’t support parameters.</p>
    pub parameters: ::std::option::Option<::std::vec::Vec<crate::types::ControlParameter>>,
    /// <p>A timestamp that notes the time when the control was released (start of its life) as a governance capability in Amazon Web Services.</p>
    pub create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A list of Amazon Web Services resource types that are governed by this control. This information helps you understand which controls can govern certain types of resources, and conversely, which resources are affected when the control is implemented. The resources are represented as Amazon Web Services CloudFormation resource types. If <code>GovernedResources</code> cannot be represented by available CloudFormation resource types, it’s returned as an empty list.</p>
    pub governed_resources: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl GetControlOutput {
    /// <p>The Amazon Resource Name (ARN) of the control.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>A list of alternative identifiers for the control. These are human-readable designators, such as <code>SH.S3.1</code>. Several aliases can refer to the same control across different Amazon Web Services services or compliance frameworks.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.aliases.is_none()`.
    pub fn aliases(&self) -> &[::std::string::String] {
        self.aliases.as_deref().unwrap_or_default()
    }
    /// <p>The display name of the control.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>A description of what the control does.</p>
    pub fn description(&self) -> &str {
        use std::ops::Deref;
        self.description.deref()
    }
    /// <p>A term that identifies the control's functional behavior. One of <code>Preventive</code>, <code>Detective</code>, <code>Proactive</code></p>
    pub fn behavior(&self) -> &crate::types::ControlBehavior {
        &self.behavior
    }
    /// <p>An enumerated type, with the following possible values:</p>
    pub fn severity(&self) -> ::std::option::Option<&crate::types::ControlSeverity> {
        self.severity.as_ref()
    }
    /// <p>Returns information about the control, including the scope of the control, if enabled, and the Regions in which the control is available for deployment. For more information about scope, see <a href="https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/global-services.html">Global services</a>.</p>
    /// <p>If you are applying controls through an Amazon Web Services Control Tower landing zone environment, remember that the values returned in the <code>RegionConfiguration</code> API operation are not related to the governed Regions in your landing zone. For example, if you are governing Regions <code>A</code>,<code>B</code>,and <code>C</code> while the control is available in Regions <code>A</code>, <code>B</code>, C<code>,</code> and <code>D</code>, you'd see a response with <code>DeployableRegions</code> of <code>A</code>, <code>B</code>, <code>C</code>, and <code>D</code> for a control with <code>REGIONAL</code> scope, even though you may not intend to deploy the control in Region <code>D</code>, because you do not govern it through your landing zone.</p>
    pub fn region_configuration(&self) -> ::std::option::Option<&crate::types::RegionConfiguration> {
        self.region_configuration.as_ref()
    }
    /// <p>Returns information about the control, as an <code>ImplementationDetails</code> object that shows the underlying implementation type for a control.</p>
    pub fn implementation(&self) -> ::std::option::Option<&crate::types::ImplementationDetails> {
        self.implementation.as_ref()
    }
    /// <p>Returns an array of <code>ControlParameter</code> objects that specify the parameters a control supports. An empty list is returned for controls that don’t support parameters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameters.is_none()`.
    pub fn parameters(&self) -> &[crate::types::ControlParameter] {
        self.parameters.as_deref().unwrap_or_default()
    }
    /// <p>A timestamp that notes the time when the control was released (start of its life) as a governance capability in Amazon Web Services.</p>
    pub fn create_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_time.as_ref()
    }
    /// <p>A list of Amazon Web Services resource types that are governed by this control. This information helps you understand which controls can govern certain types of resources, and conversely, which resources are affected when the control is implemented. The resources are represented as Amazon Web Services CloudFormation resource types. If <code>GovernedResources</code> cannot be represented by available CloudFormation resource types, it’s returned as an empty list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.governed_resources.is_none()`.
    pub fn governed_resources(&self) -> &[::std::string::String] {
        self.governed_resources.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetControlOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetControlOutput {
    /// Creates a new builder-style object to manufacture [`GetControlOutput`](crate::operation::get_control::GetControlOutput).
    pub fn builder() -> crate::operation::get_control::builders::GetControlOutputBuilder {
        crate::operation::get_control::builders::GetControlOutputBuilder::default()
    }
}

/// A builder for [`GetControlOutput`](crate::operation::get_control::GetControlOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetControlOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) aliases: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) behavior: ::std::option::Option<crate::types::ControlBehavior>,
    pub(crate) severity: ::std::option::Option<crate::types::ControlSeverity>,
    pub(crate) region_configuration: ::std::option::Option<crate::types::RegionConfiguration>,
    pub(crate) implementation: ::std::option::Option<crate::types::ImplementationDetails>,
    pub(crate) parameters: ::std::option::Option<::std::vec::Vec<crate::types::ControlParameter>>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) governed_resources: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl GetControlOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the control.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the control.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the control.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Appends an item to `aliases`.
    ///
    /// To override the contents of this collection use [`set_aliases`](Self::set_aliases).
    ///
    /// <p>A list of alternative identifiers for the control. These are human-readable designators, such as <code>SH.S3.1</code>. Several aliases can refer to the same control across different Amazon Web Services services or compliance frameworks.</p>
    pub fn aliases(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.aliases.unwrap_or_default();
        v.push(input.into());
        self.aliases = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of alternative identifiers for the control. These are human-readable designators, such as <code>SH.S3.1</code>. Several aliases can refer to the same control across different Amazon Web Services services or compliance frameworks.</p>
    pub fn set_aliases(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.aliases = input;
        self
    }
    /// <p>A list of alternative identifiers for the control. These are human-readable designators, such as <code>SH.S3.1</code>. Several aliases can refer to the same control across different Amazon Web Services services or compliance frameworks.</p>
    pub fn get_aliases(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.aliases
    }
    /// <p>The display name of the control.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the control.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The display name of the control.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of what the control does.</p>
    /// This field is required.
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of what the control does.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of what the control does.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>A term that identifies the control's functional behavior. One of <code>Preventive</code>, <code>Detective</code>, <code>Proactive</code></p>
    /// This field is required.
    pub fn behavior(mut self, input: crate::types::ControlBehavior) -> Self {
        self.behavior = ::std::option::Option::Some(input);
        self
    }
    /// <p>A term that identifies the control's functional behavior. One of <code>Preventive</code>, <code>Detective</code>, <code>Proactive</code></p>
    pub fn set_behavior(mut self, input: ::std::option::Option<crate::types::ControlBehavior>) -> Self {
        self.behavior = input;
        self
    }
    /// <p>A term that identifies the control's functional behavior. One of <code>Preventive</code>, <code>Detective</code>, <code>Proactive</code></p>
    pub fn get_behavior(&self) -> &::std::option::Option<crate::types::ControlBehavior> {
        &self.behavior
    }
    /// <p>An enumerated type, with the following possible values:</p>
    pub fn severity(mut self, input: crate::types::ControlSeverity) -> Self {
        self.severity = ::std::option::Option::Some(input);
        self
    }
    /// <p>An enumerated type, with the following possible values:</p>
    pub fn set_severity(mut self, input: ::std::option::Option<crate::types::ControlSeverity>) -> Self {
        self.severity = input;
        self
    }
    /// <p>An enumerated type, with the following possible values:</p>
    pub fn get_severity(&self) -> &::std::option::Option<crate::types::ControlSeverity> {
        &self.severity
    }
    /// <p>Returns information about the control, including the scope of the control, if enabled, and the Regions in which the control is available for deployment. For more information about scope, see <a href="https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/global-services.html">Global services</a>.</p>
    /// <p>If you are applying controls through an Amazon Web Services Control Tower landing zone environment, remember that the values returned in the <code>RegionConfiguration</code> API operation are not related to the governed Regions in your landing zone. For example, if you are governing Regions <code>A</code>,<code>B</code>,and <code>C</code> while the control is available in Regions <code>A</code>, <code>B</code>, C<code>,</code> and <code>D</code>, you'd see a response with <code>DeployableRegions</code> of <code>A</code>, <code>B</code>, <code>C</code>, and <code>D</code> for a control with <code>REGIONAL</code> scope, even though you may not intend to deploy the control in Region <code>D</code>, because you do not govern it through your landing zone.</p>
    /// This field is required.
    pub fn region_configuration(mut self, input: crate::types::RegionConfiguration) -> Self {
        self.region_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns information about the control, including the scope of the control, if enabled, and the Regions in which the control is available for deployment. For more information about scope, see <a href="https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/global-services.html">Global services</a>.</p>
    /// <p>If you are applying controls through an Amazon Web Services Control Tower landing zone environment, remember that the values returned in the <code>RegionConfiguration</code> API operation are not related to the governed Regions in your landing zone. For example, if you are governing Regions <code>A</code>,<code>B</code>,and <code>C</code> while the control is available in Regions <code>A</code>, <code>B</code>, C<code>,</code> and <code>D</code>, you'd see a response with <code>DeployableRegions</code> of <code>A</code>, <code>B</code>, <code>C</code>, and <code>D</code> for a control with <code>REGIONAL</code> scope, even though you may not intend to deploy the control in Region <code>D</code>, because you do not govern it through your landing zone.</p>
    pub fn set_region_configuration(mut self, input: ::std::option::Option<crate::types::RegionConfiguration>) -> Self {
        self.region_configuration = input;
        self
    }
    /// <p>Returns information about the control, including the scope of the control, if enabled, and the Regions in which the control is available for deployment. For more information about scope, see <a href="https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/global-services.html">Global services</a>.</p>
    /// <p>If you are applying controls through an Amazon Web Services Control Tower landing zone environment, remember that the values returned in the <code>RegionConfiguration</code> API operation are not related to the governed Regions in your landing zone. For example, if you are governing Regions <code>A</code>,<code>B</code>,and <code>C</code> while the control is available in Regions <code>A</code>, <code>B</code>, C<code>,</code> and <code>D</code>, you'd see a response with <code>DeployableRegions</code> of <code>A</code>, <code>B</code>, <code>C</code>, and <code>D</code> for a control with <code>REGIONAL</code> scope, even though you may not intend to deploy the control in Region <code>D</code>, because you do not govern it through your landing zone.</p>
    pub fn get_region_configuration(&self) -> &::std::option::Option<crate::types::RegionConfiguration> {
        &self.region_configuration
    }
    /// <p>Returns information about the control, as an <code>ImplementationDetails</code> object that shows the underlying implementation type for a control.</p>
    pub fn implementation(mut self, input: crate::types::ImplementationDetails) -> Self {
        self.implementation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns information about the control, as an <code>ImplementationDetails</code> object that shows the underlying implementation type for a control.</p>
    pub fn set_implementation(mut self, input: ::std::option::Option<crate::types::ImplementationDetails>) -> Self {
        self.implementation = input;
        self
    }
    /// <p>Returns information about the control, as an <code>ImplementationDetails</code> object that shows the underlying implementation type for a control.</p>
    pub fn get_implementation(&self) -> &::std::option::Option<crate::types::ImplementationDetails> {
        &self.implementation
    }
    /// Appends an item to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>Returns an array of <code>ControlParameter</code> objects that specify the parameters a control supports. An empty list is returned for controls that don’t support parameters.</p>
    pub fn parameters(mut self, input: crate::types::ControlParameter) -> Self {
        let mut v = self.parameters.unwrap_or_default();
        v.push(input);
        self.parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns an array of <code>ControlParameter</code> objects that specify the parameters a control supports. An empty list is returned for controls that don’t support parameters.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ControlParameter>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>Returns an array of <code>ControlParameter</code> objects that specify the parameters a control supports. An empty list is returned for controls that don’t support parameters.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ControlParameter>> {
        &self.parameters
    }
    /// <p>A timestamp that notes the time when the control was released (start of its life) as a governance capability in Amazon Web Services.</p>
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that notes the time when the control was released (start of its life) as a governance capability in Amazon Web Services.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>A timestamp that notes the time when the control was released (start of its life) as a governance capability in Amazon Web Services.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// Appends an item to `governed_resources`.
    ///
    /// To override the contents of this collection use [`set_governed_resources`](Self::set_governed_resources).
    ///
    /// <p>A list of Amazon Web Services resource types that are governed by this control. This information helps you understand which controls can govern certain types of resources, and conversely, which resources are affected when the control is implemented. The resources are represented as Amazon Web Services CloudFormation resource types. If <code>GovernedResources</code> cannot be represented by available CloudFormation resource types, it’s returned as an empty list.</p>
    pub fn governed_resources(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.governed_resources.unwrap_or_default();
        v.push(input.into());
        self.governed_resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of Amazon Web Services resource types that are governed by this control. This information helps you understand which controls can govern certain types of resources, and conversely, which resources are affected when the control is implemented. The resources are represented as Amazon Web Services CloudFormation resource types. If <code>GovernedResources</code> cannot be represented by available CloudFormation resource types, it’s returned as an empty list.</p>
    pub fn set_governed_resources(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.governed_resources = input;
        self
    }
    /// <p>A list of Amazon Web Services resource types that are governed by this control. This information helps you understand which controls can govern certain types of resources, and conversely, which resources are affected when the control is implemented. The resources are represented as Amazon Web Services CloudFormation resource types. If <code>GovernedResources</code> cannot be represented by available CloudFormation resource types, it’s returned as an empty list.</p>
    pub fn get_governed_resources(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.governed_resources
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetControlOutput`](crate::operation::get_control::GetControlOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::operation::get_control::builders::GetControlOutputBuilder::arn)
    /// - [`name`](crate::operation::get_control::builders::GetControlOutputBuilder::name)
    /// - [`description`](crate::operation::get_control::builders::GetControlOutputBuilder::description)
    /// - [`behavior`](crate::operation::get_control::builders::GetControlOutputBuilder::behavior)
    pub fn build(self) -> ::std::result::Result<crate::operation::get_control::GetControlOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_control::GetControlOutput {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building GetControlOutput",
                )
            })?,
            aliases: self.aliases,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building GetControlOutput",
                )
            })?,
            description: self.description.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "description",
                    "description was not specified but it is required when building GetControlOutput",
                )
            })?,
            behavior: self.behavior.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "behavior",
                    "behavior was not specified but it is required when building GetControlOutput",
                )
            })?,
            severity: self.severity,
            region_configuration: self.region_configuration,
            implementation: self.implementation,
            parameters: self.parameters,
            create_time: self.create_time,
            governed_resources: self.governed_resources,
            _request_id: self._request_id,
        })
    }
}
