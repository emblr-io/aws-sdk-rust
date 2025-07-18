// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteVpcPeeringAuthorizationInput {
    /// <p>A unique identifier for the Amazon Web Services account that you use to manage your Amazon GameLift Servers fleet. You can find your Account ID in the Amazon Web Services Management Console under account settings.</p>
    pub game_lift_aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for a VPC with resources to be accessed by your Amazon GameLift Servers fleet. The VPC must be in the same Region as your fleet. To look up a VPC ID, use the <a href="https://console.aws.amazon.com/vpc/">VPC Dashboard</a> in the Amazon Web Services Management Console. Learn more about VPC peering in <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/vpc-peering.html">VPC Peering with Amazon GameLift Servers Fleets</a>.</p>
    pub peer_vpc_id: ::std::option::Option<::std::string::String>,
}
impl DeleteVpcPeeringAuthorizationInput {
    /// <p>A unique identifier for the Amazon Web Services account that you use to manage your Amazon GameLift Servers fleet. You can find your Account ID in the Amazon Web Services Management Console under account settings.</p>
    pub fn game_lift_aws_account_id(&self) -> ::std::option::Option<&str> {
        self.game_lift_aws_account_id.as_deref()
    }
    /// <p>A unique identifier for a VPC with resources to be accessed by your Amazon GameLift Servers fleet. The VPC must be in the same Region as your fleet. To look up a VPC ID, use the <a href="https://console.aws.amazon.com/vpc/">VPC Dashboard</a> in the Amazon Web Services Management Console. Learn more about VPC peering in <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/vpc-peering.html">VPC Peering with Amazon GameLift Servers Fleets</a>.</p>
    pub fn peer_vpc_id(&self) -> ::std::option::Option<&str> {
        self.peer_vpc_id.as_deref()
    }
}
impl DeleteVpcPeeringAuthorizationInput {
    /// Creates a new builder-style object to manufacture [`DeleteVpcPeeringAuthorizationInput`](crate::operation::delete_vpc_peering_authorization::DeleteVpcPeeringAuthorizationInput).
    pub fn builder() -> crate::operation::delete_vpc_peering_authorization::builders::DeleteVpcPeeringAuthorizationInputBuilder {
        crate::operation::delete_vpc_peering_authorization::builders::DeleteVpcPeeringAuthorizationInputBuilder::default()
    }
}

/// A builder for [`DeleteVpcPeeringAuthorizationInput`](crate::operation::delete_vpc_peering_authorization::DeleteVpcPeeringAuthorizationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteVpcPeeringAuthorizationInputBuilder {
    pub(crate) game_lift_aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) peer_vpc_id: ::std::option::Option<::std::string::String>,
}
impl DeleteVpcPeeringAuthorizationInputBuilder {
    /// <p>A unique identifier for the Amazon Web Services account that you use to manage your Amazon GameLift Servers fleet. You can find your Account ID in the Amazon Web Services Management Console under account settings.</p>
    /// This field is required.
    pub fn game_lift_aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.game_lift_aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the Amazon Web Services account that you use to manage your Amazon GameLift Servers fleet. You can find your Account ID in the Amazon Web Services Management Console under account settings.</p>
    pub fn set_game_lift_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.game_lift_aws_account_id = input;
        self
    }
    /// <p>A unique identifier for the Amazon Web Services account that you use to manage your Amazon GameLift Servers fleet. You can find your Account ID in the Amazon Web Services Management Console under account settings.</p>
    pub fn get_game_lift_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.game_lift_aws_account_id
    }
    /// <p>A unique identifier for a VPC with resources to be accessed by your Amazon GameLift Servers fleet. The VPC must be in the same Region as your fleet. To look up a VPC ID, use the <a href="https://console.aws.amazon.com/vpc/">VPC Dashboard</a> in the Amazon Web Services Management Console. Learn more about VPC peering in <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/vpc-peering.html">VPC Peering with Amazon GameLift Servers Fleets</a>.</p>
    /// This field is required.
    pub fn peer_vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.peer_vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for a VPC with resources to be accessed by your Amazon GameLift Servers fleet. The VPC must be in the same Region as your fleet. To look up a VPC ID, use the <a href="https://console.aws.amazon.com/vpc/">VPC Dashboard</a> in the Amazon Web Services Management Console. Learn more about VPC peering in <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/vpc-peering.html">VPC Peering with Amazon GameLift Servers Fleets</a>.</p>
    pub fn set_peer_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.peer_vpc_id = input;
        self
    }
    /// <p>A unique identifier for a VPC with resources to be accessed by your Amazon GameLift Servers fleet. The VPC must be in the same Region as your fleet. To look up a VPC ID, use the <a href="https://console.aws.amazon.com/vpc/">VPC Dashboard</a> in the Amazon Web Services Management Console. Learn more about VPC peering in <a href="https://docs.aws.amazon.com/gamelift/latest/developerguide/vpc-peering.html">VPC Peering with Amazon GameLift Servers Fleets</a>.</p>
    pub fn get_peer_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.peer_vpc_id
    }
    /// Consumes the builder and constructs a [`DeleteVpcPeeringAuthorizationInput`](crate::operation::delete_vpc_peering_authorization::DeleteVpcPeeringAuthorizationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_vpc_peering_authorization::DeleteVpcPeeringAuthorizationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_vpc_peering_authorization::DeleteVpcPeeringAuthorizationInput {
            game_lift_aws_account_id: self.game_lift_aws_account_id,
            peer_vpc_id: self.peer_vpc_id,
        })
    }
}
