package auth2

import "testing"

func TestUser_SendResetMailer(t *testing.T) {
	type fields struct {
		Email    string
		Password string
		UserID   string
		Role     string
		Approved bool
		Data     interface{}
		IPAddr   string
	}
	type args struct {
		message  string
		password string
		emp      EmailParams
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.

		{name: "test1",
			fields: fields{Email: "omfaluyi@gmail.com"},
			args: args{
				"Hello, Guyman, your password has been reset by your admin...",
				"nuP45S3355",
				EmailParams{"osas@788.ng",
					"Andro7887@",
					"smtp.gmail.com",
					"587"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{
				Email:    tt.fields.Email,
				Password: tt.fields.Password,
				UserID:   tt.fields.UserID,
				Role:     tt.fields.Role,
				Approved: tt.fields.Approved,
				Data:     tt.fields.Data,
				IPAddr:   tt.fields.IPAddr,
			}
			if err := u.SendResetMailer(tt.args.message, tt.args.password, tt.args.emp); (err != nil) != tt.wantErr {
				t.Errorf("SendResetMailer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
