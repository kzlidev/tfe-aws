# Create a public Elastic IP
resource "aws_eip" "my_public_ip" {
  domain = "vpc"
}