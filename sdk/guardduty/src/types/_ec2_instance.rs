// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the potentially impacted Amazon EC2 instance resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Ec2Instance {
    /// <p>The availability zone of the Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-availability-zones">Availability zones</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>The image description of the Amazon EC2 instance.</p>
    pub image_description: ::std::option::Option<::std::string::String>,
    /// <p>The state of the Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html">Amazon EC2 instance state changes</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub instance_state: ::std::option::Option<::std::string::String>,
    /// <p>Contains information about the EC2 instance profile.</p>
    pub iam_instance_profile: ::std::option::Option<crate::types::IamInstanceProfile>,
    /// <p>Type of the Amazon EC2 instance.</p>
    pub instance_type: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the Amazon Web Services Outpost. This shows applicable Amazon Web Services Outposts instances.</p>
    pub outpost_arn: ::std::option::Option<::std::string::String>,
    /// <p>The platform of the Amazon EC2 instance.</p>
    pub platform: ::std::option::Option<::std::string::String>,
    /// <p>The product code of the Amazon EC2 instance.</p>
    pub product_codes: ::std::option::Option<::std::vec::Vec<crate::types::ProductCode>>,
    /// <p>The ID of the network interface.</p>
    pub ec2_network_interface_uids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl Ec2Instance {
    /// <p>The availability zone of the Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-availability-zones">Availability zones</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>The image description of the Amazon EC2 instance.</p>
    pub fn image_description(&self) -> ::std::option::Option<&str> {
        self.image_description.as_deref()
    }
    /// <p>The state of the Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html">Amazon EC2 instance state changes</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn instance_state(&self) -> ::std::option::Option<&str> {
        self.instance_state.as_deref()
    }
    /// <p>Contains information about the EC2 instance profile.</p>
    pub fn iam_instance_profile(&self) -> ::std::option::Option<&crate::types::IamInstanceProfile> {
        self.iam_instance_profile.as_ref()
    }
    /// <p>Type of the Amazon EC2 instance.</p>
    pub fn instance_type(&self) -> ::std::option::Option<&str> {
        self.instance_type.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Web Services Outpost. This shows applicable Amazon Web Services Outposts instances.</p>
    pub fn outpost_arn(&self) -> ::std::option::Option<&str> {
        self.outpost_arn.as_deref()
    }
    /// <p>The platform of the Amazon EC2 instance.</p>
    pub fn platform(&self) -> ::std::option::Option<&str> {
        self.platform.as_deref()
    }
    /// <p>The product code of the Amazon EC2 instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.product_codes.is_none()`.
    pub fn product_codes(&self) -> &[crate::types::ProductCode] {
        self.product_codes.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the network interface.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ec2_network_interface_uids.is_none()`.
    pub fn ec2_network_interface_uids(&self) -> &[::std::string::String] {
        self.ec2_network_interface_uids.as_deref().unwrap_or_default()
    }
}
impl Ec2Instance {
    /// Creates a new builder-style object to manufacture [`Ec2Instance`](crate::types::Ec2Instance).
    pub fn builder() -> crate::types::builders::Ec2InstanceBuilder {
        crate::types::builders::Ec2InstanceBuilder::default()
    }
}

/// A builder for [`Ec2Instance`](crate::types::Ec2Instance).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Ec2InstanceBuilder {
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) image_description: ::std::option::Option<::std::string::String>,
    pub(crate) instance_state: ::std::option::Option<::std::string::String>,
    pub(crate) iam_instance_profile: ::std::option::Option<crate::types::IamInstanceProfile>,
    pub(crate) instance_type: ::std::option::Option<::std::string::String>,
    pub(crate) outpost_arn: ::std::option::Option<::std::string::String>,
    pub(crate) platform: ::std::option::Option<::std::string::String>,
    pub(crate) product_codes: ::std::option::Option<::std::vec::Vec<crate::types::ProductCode>>,
    pub(crate) ec2_network_interface_uids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl Ec2InstanceBuilder {
    /// <p>The availability zone of the Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-availability-zones">Availability zones</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The availability zone of the Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-availability-zones">Availability zones</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>The availability zone of the Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-availability-zones">Availability zones</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// <p>The image description of the Amazon EC2 instance.</p>
    pub fn image_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The image description of the Amazon EC2 instance.</p>
    pub fn set_image_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_description = input;
        self
    }
    /// <p>The image description of the Amazon EC2 instance.</p>
    pub fn get_image_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_description
    }
    /// <p>The state of the Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html">Amazon EC2 instance state changes</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn instance_state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The state of the Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html">Amazon EC2 instance state changes</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn set_instance_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_state = input;
        self
    }
    /// <p>The state of the Amazon EC2 instance. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html">Amazon EC2 instance state changes</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn get_instance_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_state
    }
    /// <p>Contains information about the EC2 instance profile.</p>
    pub fn iam_instance_profile(mut self, input: crate::types::IamInstanceProfile) -> Self {
        self.iam_instance_profile = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the EC2 instance profile.</p>
    pub fn set_iam_instance_profile(mut self, input: ::std::option::Option<crate::types::IamInstanceProfile>) -> Self {
        self.iam_instance_profile = input;
        self
    }
    /// <p>Contains information about the EC2 instance profile.</p>
    pub fn get_iam_instance_profile(&self) -> &::std::option::Option<crate::types::IamInstanceProfile> {
        &self.iam_instance_profile
    }
    /// <p>Type of the Amazon EC2 instance.</p>
    pub fn instance_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Type of the Amazon EC2 instance.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>Type of the Amazon EC2 instance.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_type
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Web Services Outpost. This shows applicable Amazon Web Services Outposts instances.</p>
    pub fn outpost_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.outpost_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Web Services Outpost. This shows applicable Amazon Web Services Outposts instances.</p>
    pub fn set_outpost_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.outpost_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon Web Services Outpost. This shows applicable Amazon Web Services Outposts instances.</p>
    pub fn get_outpost_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.outpost_arn
    }
    /// <p>The platform of the Amazon EC2 instance.</p>
    pub fn platform(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.platform = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The platform of the Amazon EC2 instance.</p>
    pub fn set_platform(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.platform = input;
        self
    }
    /// <p>The platform of the Amazon EC2 instance.</p>
    pub fn get_platform(&self) -> &::std::option::Option<::std::string::String> {
        &self.platform
    }
    /// Appends an item to `product_codes`.
    ///
    /// To override the contents of this collection use [`set_product_codes`](Self::set_product_codes).
    ///
    /// <p>The product code of the Amazon EC2 instance.</p>
    pub fn product_codes(mut self, input: crate::types::ProductCode) -> Self {
        let mut v = self.product_codes.unwrap_or_default();
        v.push(input);
        self.product_codes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The product code of the Amazon EC2 instance.</p>
    pub fn set_product_codes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ProductCode>>) -> Self {
        self.product_codes = input;
        self
    }
    /// <p>The product code of the Amazon EC2 instance.</p>
    pub fn get_product_codes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ProductCode>> {
        &self.product_codes
    }
    /// Appends an item to `ec2_network_interface_uids`.
    ///
    /// To override the contents of this collection use [`set_ec2_network_interface_uids`](Self::set_ec2_network_interface_uids).
    ///
    /// <p>The ID of the network interface.</p>
    pub fn ec2_network_interface_uids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ec2_network_interface_uids.unwrap_or_default();
        v.push(input.into());
        self.ec2_network_interface_uids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ID of the network interface.</p>
    pub fn set_ec2_network_interface_uids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ec2_network_interface_uids = input;
        self
    }
    /// <p>The ID of the network interface.</p>
    pub fn get_ec2_network_interface_uids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ec2_network_interface_uids
    }
    /// Consumes the builder and constructs a [`Ec2Instance`](crate::types::Ec2Instance).
    pub fn build(self) -> crate::types::Ec2Instance {
        crate::types::Ec2Instance {
            availability_zone: self.availability_zone,
            image_description: self.image_description,
            instance_state: self.instance_state,
            iam_instance_profile: self.iam_instance_profile,
            instance_type: self.instance_type,
            outpost_arn: self.outpost_arn,
            platform: self.platform,
            product_codes: self.product_codes,
            ec2_network_interface_uids: self.ec2_network_interface_uids,
        }
    }
}
