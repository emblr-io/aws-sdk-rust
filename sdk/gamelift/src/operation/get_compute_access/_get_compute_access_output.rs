// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GetComputeAccessOutput {
    /// <p>The ID of the fleet that holds the compute resource to be accessed.</p>
    pub fleet_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html">ARN</a>) that is assigned to a Amazon GameLift Servers fleet resource and uniquely identifies it. ARNs are unique across all Regions. Format is <code>arn:aws:gamelift:<region>
    /// ::fleet/fleet-a1234567-b8c9-0d1e-2fa3-b45c6d7e8912
    /// </region></code>.</p>
    pub fleet_arn: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the compute resource to be accessed. This value might be either a compute name or an instance ID.</p>
    pub compute_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html">ARN</a>) that is assigned to an Amazon GameLift Servers compute resource and uniquely identifies it. ARNs are unique across all Regions. Format is <code>arn:aws:gamelift:<region>
    /// ::compute/compute-a1234567-b8c9-0d1e-2fa3-b45c6d7e8912
    /// </region></code>.</p>
    pub compute_arn: ::std::option::Option<::std::string::String>,
    /// <p>A set of temporary Amazon Web Services credentials for use when connecting to the compute resource with Amazon EC2 Systems Manager (SSM).</p>
    pub credentials: ::std::option::Option<crate::types::AwsCredentials>,
    /// <p>The instance ID where the compute resource is running.</p>
    pub target: ::std::option::Option<::std::string::String>,
    /// <p>For a managed container fleet, a list of containers on the compute. Use the container runtime ID with Docker commands to connect to a specific container.</p>
    pub container_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::ContainerIdentifier>>,
    _request_id: Option<String>,
}
impl GetComputeAccessOutput {
    /// <p>The ID of the fleet that holds the compute resource to be accessed.</p>
    pub fn fleet_id(&self) -> ::std::option::Option<&str> {
        self.fleet_id.as_deref()
    }
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html">ARN</a>) that is assigned to a Amazon GameLift Servers fleet resource and uniquely identifies it. ARNs are unique across all Regions. Format is <code>arn:aws:gamelift:<region>
    /// ::fleet/fleet-a1234567-b8c9-0d1e-2fa3-b45c6d7e8912
    /// </region></code>.</p>
    pub fn fleet_arn(&self) -> ::std::option::Option<&str> {
        self.fleet_arn.as_deref()
    }
    /// <p>The identifier of the compute resource to be accessed. This value might be either a compute name or an instance ID.</p>
    pub fn compute_name(&self) -> ::std::option::Option<&str> {
        self.compute_name.as_deref()
    }
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html">ARN</a>) that is assigned to an Amazon GameLift Servers compute resource and uniquely identifies it. ARNs are unique across all Regions. Format is <code>arn:aws:gamelift:<region>
    /// ::compute/compute-a1234567-b8c9-0d1e-2fa3-b45c6d7e8912
    /// </region></code>.</p>
    pub fn compute_arn(&self) -> ::std::option::Option<&str> {
        self.compute_arn.as_deref()
    }
    /// <p>A set of temporary Amazon Web Services credentials for use when connecting to the compute resource with Amazon EC2 Systems Manager (SSM).</p>
    pub fn credentials(&self) -> ::std::option::Option<&crate::types::AwsCredentials> {
        self.credentials.as_ref()
    }
    /// <p>The instance ID where the compute resource is running.</p>
    pub fn target(&self) -> ::std::option::Option<&str> {
        self.target.as_deref()
    }
    /// <p>For a managed container fleet, a list of containers on the compute. Use the container runtime ID with Docker commands to connect to a specific container.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.container_identifiers.is_none()`.
    pub fn container_identifiers(&self) -> &[crate::types::ContainerIdentifier] {
        self.container_identifiers.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for GetComputeAccessOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetComputeAccessOutput");
        formatter.field("fleet_id", &self.fleet_id);
        formatter.field("fleet_arn", &self.fleet_arn);
        formatter.field("compute_name", &self.compute_name);
        formatter.field("compute_arn", &self.compute_arn);
        formatter.field("credentials", &"*** Sensitive Data Redacted ***");
        formatter.field("target", &self.target);
        formatter.field("container_identifiers", &self.container_identifiers);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for GetComputeAccessOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetComputeAccessOutput {
    /// Creates a new builder-style object to manufacture [`GetComputeAccessOutput`](crate::operation::get_compute_access::GetComputeAccessOutput).
    pub fn builder() -> crate::operation::get_compute_access::builders::GetComputeAccessOutputBuilder {
        crate::operation::get_compute_access::builders::GetComputeAccessOutputBuilder::default()
    }
}

/// A builder for [`GetComputeAccessOutput`](crate::operation::get_compute_access::GetComputeAccessOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GetComputeAccessOutputBuilder {
    pub(crate) fleet_id: ::std::option::Option<::std::string::String>,
    pub(crate) fleet_arn: ::std::option::Option<::std::string::String>,
    pub(crate) compute_name: ::std::option::Option<::std::string::String>,
    pub(crate) compute_arn: ::std::option::Option<::std::string::String>,
    pub(crate) credentials: ::std::option::Option<crate::types::AwsCredentials>,
    pub(crate) target: ::std::option::Option<::std::string::String>,
    pub(crate) container_identifiers: ::std::option::Option<::std::vec::Vec<crate::types::ContainerIdentifier>>,
    _request_id: Option<String>,
}
impl GetComputeAccessOutputBuilder {
    /// <p>The ID of the fleet that holds the compute resource to be accessed.</p>
    pub fn fleet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the fleet that holds the compute resource to be accessed.</p>
    pub fn set_fleet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet_id = input;
        self
    }
    /// <p>The ID of the fleet that holds the compute resource to be accessed.</p>
    pub fn get_fleet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet_id
    }
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html">ARN</a>) that is assigned to a Amazon GameLift Servers fleet resource and uniquely identifies it. ARNs are unique across all Regions. Format is <code>arn:aws:gamelift:<region>
    /// ::fleet/fleet-a1234567-b8c9-0d1e-2fa3-b45c6d7e8912
    /// </region></code>.</p>
    pub fn fleet_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html">ARN</a>) that is assigned to a Amazon GameLift Servers fleet resource and uniquely identifies it. ARNs are unique across all Regions. Format is <code>arn:aws:gamelift:<region>
    /// ::fleet/fleet-a1234567-b8c9-0d1e-2fa3-b45c6d7e8912
    /// </region></code>.</p>
    pub fn set_fleet_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html">ARN</a>) that is assigned to a Amazon GameLift Servers fleet resource and uniquely identifies it. ARNs are unique across all Regions. Format is <code>arn:aws:gamelift:<region>
    /// ::fleet/fleet-a1234567-b8c9-0d1e-2fa3-b45c6d7e8912
    /// </region></code>.</p>
    pub fn get_fleet_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet_arn
    }
    /// <p>The identifier of the compute resource to be accessed. This value might be either a compute name or an instance ID.</p>
    pub fn compute_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.compute_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the compute resource to be accessed. This value might be either a compute name or an instance ID.</p>
    pub fn set_compute_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.compute_name = input;
        self
    }
    /// <p>The identifier of the compute resource to be accessed. This value might be either a compute name or an instance ID.</p>
    pub fn get_compute_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.compute_name
    }
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html">ARN</a>) that is assigned to an Amazon GameLift Servers compute resource and uniquely identifies it. ARNs are unique across all Regions. Format is <code>arn:aws:gamelift:<region>
    /// ::compute/compute-a1234567-b8c9-0d1e-2fa3-b45c6d7e8912
    /// </region></code>.</p>
    pub fn compute_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.compute_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html">ARN</a>) that is assigned to an Amazon GameLift Servers compute resource and uniquely identifies it. ARNs are unique across all Regions. Format is <code>arn:aws:gamelift:<region>
    /// ::compute/compute-a1234567-b8c9-0d1e-2fa3-b45c6d7e8912
    /// </region></code>.</p>
    pub fn set_compute_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.compute_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/s3-arn-format.html">ARN</a>) that is assigned to an Amazon GameLift Servers compute resource and uniquely identifies it. ARNs are unique across all Regions. Format is <code>arn:aws:gamelift:<region>
    /// ::compute/compute-a1234567-b8c9-0d1e-2fa3-b45c6d7e8912
    /// </region></code>.</p>
    pub fn get_compute_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.compute_arn
    }
    /// <p>A set of temporary Amazon Web Services credentials for use when connecting to the compute resource with Amazon EC2 Systems Manager (SSM).</p>
    pub fn credentials(mut self, input: crate::types::AwsCredentials) -> Self {
        self.credentials = ::std::option::Option::Some(input);
        self
    }
    /// <p>A set of temporary Amazon Web Services credentials for use when connecting to the compute resource with Amazon EC2 Systems Manager (SSM).</p>
    pub fn set_credentials(mut self, input: ::std::option::Option<crate::types::AwsCredentials>) -> Self {
        self.credentials = input;
        self
    }
    /// <p>A set of temporary Amazon Web Services credentials for use when connecting to the compute resource with Amazon EC2 Systems Manager (SSM).</p>
    pub fn get_credentials(&self) -> &::std::option::Option<crate::types::AwsCredentials> {
        &self.credentials
    }
    /// <p>The instance ID where the compute resource is running.</p>
    pub fn target(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The instance ID where the compute resource is running.</p>
    pub fn set_target(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target = input;
        self
    }
    /// <p>The instance ID where the compute resource is running.</p>
    pub fn get_target(&self) -> &::std::option::Option<::std::string::String> {
        &self.target
    }
    /// Appends an item to `container_identifiers`.
    ///
    /// To override the contents of this collection use [`set_container_identifiers`](Self::set_container_identifiers).
    ///
    /// <p>For a managed container fleet, a list of containers on the compute. Use the container runtime ID with Docker commands to connect to a specific container.</p>
    pub fn container_identifiers(mut self, input: crate::types::ContainerIdentifier) -> Self {
        let mut v = self.container_identifiers.unwrap_or_default();
        v.push(input);
        self.container_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>For a managed container fleet, a list of containers on the compute. Use the container runtime ID with Docker commands to connect to a specific container.</p>
    pub fn set_container_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ContainerIdentifier>>) -> Self {
        self.container_identifiers = input;
        self
    }
    /// <p>For a managed container fleet, a list of containers on the compute. Use the container runtime ID with Docker commands to connect to a specific container.</p>
    pub fn get_container_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ContainerIdentifier>> {
        &self.container_identifiers
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetComputeAccessOutput`](crate::operation::get_compute_access::GetComputeAccessOutput).
    pub fn build(self) -> crate::operation::get_compute_access::GetComputeAccessOutput {
        crate::operation::get_compute_access::GetComputeAccessOutput {
            fleet_id: self.fleet_id,
            fleet_arn: self.fleet_arn,
            compute_name: self.compute_name,
            compute_arn: self.compute_arn,
            credentials: self.credentials,
            target: self.target,
            container_identifiers: self.container_identifiers,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for GetComputeAccessOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetComputeAccessOutputBuilder");
        formatter.field("fleet_id", &self.fleet_id);
        formatter.field("fleet_arn", &self.fleet_arn);
        formatter.field("compute_name", &self.compute_name);
        formatter.field("compute_arn", &self.compute_arn);
        formatter.field("credentials", &"*** Sensitive Data Redacted ***");
        formatter.field("target", &self.target);
        formatter.field("container_identifiers", &self.container_identifiers);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
