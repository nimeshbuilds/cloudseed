output "public_ip" { value = aws_eip.bastion.public_ip }
output "private_ip" { value = aws_instance.bastion.private_ip }
output "instance_id" { value = aws_instance.bastion.id }
output "security_group_id" { value = aws_security_group.bastion.id }
output "workload_security_group_id" { value = aws_security_group.workload.id }
output "iam_role_arn" { value = aws_iam_role.bastion.arn }
output "iam_role_name" { value = aws_iam_role.bastion.name }
output "key_name" { value = aws_key_pair.bastion.key_name }
